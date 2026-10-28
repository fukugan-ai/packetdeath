//! WebAuthn registration and assertion checks. `webapp/docs/design.ja.md` stage 14.
//!
//! ES256 (P-256, SHA-256) only, attestation "none" only: the console wants a key
//! that belongs to the person, not a statement about the device. A relying party
//! is one id and one origin, fixed at start; a credential made for another name
//! does not verify. Every check the W3C steps name for these two ceremonies and
//! that matters here is done: the type, the challenge, the origin, the hash of
//! the relying party id, the user-present flag, the signature and the counter.

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::cbor;

/// The relying party: the registrable name the keys are bound to, and the origin the page is served from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relying {
    pub id: String,
    pub origin: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WebauthnError {
    Encoding,
    ClientData,
    Challenge,
    Origin,
    RpHash,
    Flags,
    AuthData,
    Key,
    Signature,
    Counter,
}

impl std::fmt::Display for WebauthnError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let why = match self {
            WebauthnError::Encoding => "an answer field is not base64url",
            WebauthnError::ClientData => "the client data is not the expected JSON",
            WebauthnError::Challenge => "the challenge does not match",
            WebauthnError::Origin => "the origin does not match this console",
            WebauthnError::RpHash => "the relying party hash does not match",
            WebauthnError::Flags => "the user-present flag is missing",
            WebauthnError::AuthData => "the authenticator data cannot be read",
            WebauthnError::Key => "the public key is not an ES256 key",
            WebauthnError::Signature => "the signature does not verify",
            WebauthnError::Counter => "the signature counter did not go up",
        };
        out.write_str(why)
    }
}

impl std::error::Error for WebauthnError {}

/// A key that registration produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Registered {
    pub credential_id: Vec<u8>,
    /// SEC1 uncompressed point, 65 bytes.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

pub fn b64(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>, WebauthnError> {
    BASE64URL_NOPAD.decode(text.as_bytes()).map_err(|_| WebauthnError::Encoding)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What `navigator.credentials.create` is asked for.
pub fn registration_options(rp: &Relying, user_id: &[u8], user_name: &str, challenge: &[u8], exclude: &[Vec<u8>]) -> Value {
    let excluded: Vec<Value> = exclude.iter().map(|id| json!({"type": "public-key", "id": b64(id)})).collect();
    json!({
        "challenge": b64(challenge),
        "rp": {"id": rp.id, "name": "packetdeath"},
        "user": {"id": b64(user_id), "name": user_name, "displayName": user_name},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "excludeCredentials": excluded,
        "authenticatorSelection": {"userVerification": "preferred", "residentKey": "preferred"},
        "attestation": "none",
        "timeout": 60000,
    })
}

/// What `navigator.credentials.get` is asked for.
pub fn assertion_options(rp: &Relying, challenge: &[u8], allow: &[Vec<u8>]) -> Value {
    let allowed: Vec<Value> = allow.iter().map(|id| json!({"type": "public-key", "id": b64(id)})).collect();
    json!({
        "challenge": b64(challenge),
        "rpId": rp.id,
        "allowCredentials": allowed,
        "userVerification": "preferred",
        "timeout": 60000,
    })
}

fn check_client_data(rp: &Relying, kind: &str, challenge: &[u8], client_data: &[u8]) -> Result<(), WebauthnError> {
    let parsed: Value = serde_json::from_slice(client_data).map_err(|_| WebauthnError::ClientData)?;
    if parsed.get("type").and_then(Value::as_str) != Some(kind) {
        return Err(WebauthnError::ClientData);
    }
    let sent = parsed.get("challenge").and_then(Value::as_str).ok_or(WebauthnError::ClientData)?;
    let sent = unb64(sent)?;
    if !bool::from(sent.as_slice().ct_eq(challenge)) {
        return Err(WebauthnError::Challenge);
    }
    if parsed.get("origin").and_then(Value::as_str) != Some(rp.origin.as_str()) {
        return Err(WebauthnError::Origin);
    }
    if parsed.get("crossOrigin").and_then(Value::as_bool) == Some(true) {
        return Err(WebauthnError::Origin);
    }
    Ok(())
}

/// The fixed head of the authenticator data: flags and counter (the relying party hash is checked on the way).
struct Head {
    flags: u8,
    count: u32,
}

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_ATTESTED: u8 = 0x40;

fn auth_head(rp: &Relying, auth_data: &[u8]) -> Result<Head, WebauthnError> {
    let fixed = auth_data.get(..37).ok_or(WebauthnError::AuthData)?;
    let hash = fixed.get(..32).ok_or(WebauthnError::AuthData)?;
    if !bool::from(hash.ct_eq(&sha256(rp.id.as_bytes()))) {
        return Err(WebauthnError::RpHash);
    }
    let flags = *fixed.get(32).ok_or(WebauthnError::AuthData)?;
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(WebauthnError::Flags);
    }
    let counter = fixed.get(33..37).ok_or(WebauthnError::AuthData)?;
    let mut word = [0_u8; 4];
    word.copy_from_slice(counter);
    Ok(Head { flags, count: u32::from_be_bytes(word) })
}

fn key_of(cose: &cbor::Value) -> Result<Vec<u8>, WebauthnError> {
    let kind = cose.by_int(1).and_then(cbor::Value::as_int);
    let alg = cose.by_int(3).and_then(cbor::Value::as_int);
    let curve = cose.by_int(-1).and_then(cbor::Value::as_int);
    if (kind, alg, curve) != (Some(2), Some(-7), Some(1)) {
        return Err(WebauthnError::Key);
    }
    let x = cose.by_int(-2).and_then(cbor::Value::as_bytes).ok_or(WebauthnError::Key)?;
    let y = cose.by_int(-3).and_then(cbor::Value::as_bytes).ok_or(WebauthnError::Key)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(WebauthnError::Key);
    }
    let mut point = vec![0x04_u8];
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    // A point that is not on the curve is refused here, not at the first sign-in.
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| WebauthnError::Key)?;
    Ok(point)
}

/// Check a `create` answer and return the key to keep.
pub fn finish_registration(rp: &Relying, challenge: &[u8], client_data: &[u8], attestation_object: &[u8]) -> Result<Registered, WebauthnError> {
    check_client_data(rp, "webauthn.create", challenge, client_data)?;
    let object = cbor::read_all(attestation_object).map_err(|_| WebauthnError::AuthData)?;
    let auth_data = object.by_text("authData").and_then(cbor::Value::as_bytes).ok_or(WebauthnError::AuthData)?;
    let head = auth_head(rp, auth_data)?;
    if head.flags & FLAG_ATTESTED == 0 {
        return Err(WebauthnError::AuthData);
    }
    let length_bytes = auth_data.get(53..55).ok_or(WebauthnError::AuthData)?;
    let id_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    if id_length == 0 || id_length > 1023 {
        return Err(WebauthnError::AuthData);
    }
    let credential_id = auth_data.get(55..55 + id_length).ok_or(WebauthnError::AuthData)?.to_vec();
    let rest = auth_data.get(55 + id_length..).ok_or(WebauthnError::AuthData)?;
    let (cose, _) = cbor::read(rest).map_err(|_| WebauthnError::Key)?;
    Ok(Registered { credential_id, public_key: key_of(&cose)?, sign_count: head.count })
}

/// Check a `get` answer against a kept key and return the new counter.
pub fn finish_assertion(rp: &Relying, challenge: &[u8], public_key: &[u8], stored_count: u32, auth_data: &[u8], client_data: &[u8], signature: &[u8]) -> Result<u32, WebauthnError> {
    check_client_data(rp, "webauthn.get", challenge, client_data)?;
    let head = auth_head(rp, auth_data)?;
    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| WebauthnError::Key)?;
    let signature = Signature::from_der(signature).map_err(|_| WebauthnError::Signature)?;
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&sha256(client_data));
    key.verify(&signed, &signature).map_err(|_| WebauthnError::Signature)?;
    // A counter that stays at zero is an authenticator without one; any other must rise.
    if (head.count != 0 || stored_count != 0) && head.count <= stored_count {
        return Err(WebauthnError::Counter);
    }
    Ok(head.count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    fn rp() -> Relying {
        Relying { id: String::from("console.example.org"), origin: String::from("https://console.example.org") }
    }

    fn key() -> Result<SigningKey, Box<dyn std::error::Error>> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed)?;
        Ok(SigningKey::from_slice(&seed)?)
    }

    fn cbor_head(major: u8, length: usize) -> Vec<u8> {
        match length {
            0..=23 => vec![(major << 5) | length as u8],
            24..=255 => vec![(major << 5) | 24, length as u8],
            _ => vec![(major << 5) | 25, (length >> 8) as u8, length as u8],
        }
    }

    fn cbor_text(text: &str) -> Vec<u8> {
        let mut out = cbor_head(3, text.len());
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn cbor_bytes(raw: &[u8]) -> Vec<u8> {
        let mut out = cbor_head(2, raw.len());
        out.extend_from_slice(raw);
        out
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": b64(challenge), "origin": origin}).to_string().into_bytes()
    }

    fn auth_data_for(rp: &Relying, flags: u8, count: u32, attested: Option<(&[u8], &SigningKey)>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut out = sha256(rp.id.as_bytes()).to_vec();
        out.push(flags);
        out.extend_from_slice(&count.to_be_bytes());
        if let Some((id, signing)) = attested {
            out.extend_from_slice(&[0_u8; 16]);
            out.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
            out.extend_from_slice(id);
            let point = signing.verifying_key().to_sec1_bytes();
            let (x, y) = (point.get(1..33).ok_or("no x")?, point.get(33..65).ok_or("no y")?);
            out.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
            out.extend_from_slice(x);
            out.extend_from_slice(&[0x22, 0x58, 0x20]);
            out.extend_from_slice(y);
        }
        Ok(out)
    }

    fn attestation(auth_data: &[u8]) -> Vec<u8> {
        let mut out = vec![0xa3];
        out.extend(cbor_text("fmt"));
        out.extend(cbor_text("none"));
        out.extend(cbor_text("attStmt"));
        out.push(0xa0);
        out.extend(cbor_text("authData"));
        out.extend(cbor_bytes(auth_data));
        out
    }

    fn registered() -> Result<(SigningKey, Registered), Box<dyn std::error::Error>> {
        let signing = key()?;
        let challenge = [7_u8; 32];
        let data = auth_data_for(&rp(), 0x45, 0, Some((&[9_u8; 16], &signing)))?;
        let made = finish_registration(&rp(), &challenge, &client_data("webauthn.create", &challenge, &rp().origin), &attestation(&data))?;
        Ok((signing, made))
    }

    fn assertion(signing: &SigningKey, challenge: &[u8], count: u32, flags: u8, origin: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let data = auth_data_for(&rp(), flags, count, None)?;
        let client = client_data("webauthn.get", challenge, origin);
        let mut signed = data.clone();
        signed.extend_from_slice(&sha256(&client));
        let signature: Signature = signing.sign(&signed);
        Ok((data, client, signature.to_der().as_bytes().to_vec()))
    }

    #[test]
    fn a_registration_yields_the_key_and_the_id() -> Result<(), Box<dyn std::error::Error>> {
        let (signing, made) = registered()?;
        assert_eq!(made.credential_id, vec![9_u8; 16]);
        assert_eq!(made.public_key.as_slice(), &*signing.verifying_key().to_sec1_bytes());
        assert_eq!(made.sign_count, 0);
        Ok(())
    }

    #[test]
    fn a_registration_for_another_challenge_origin_or_name_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let signing = key()?;
        let challenge = [7_u8; 32];
        let data = auth_data_for(&rp(), 0x45, 0, Some((&[9_u8; 16], &signing)))?;
        let object = attestation(&data);
        let other_challenge = client_data("webauthn.create", &[8_u8; 32], &rp().origin);
        assert_eq!(finish_registration(&rp(), &challenge, &other_challenge, &object), Err(WebauthnError::Challenge));
        let other_origin = client_data("webauthn.create", &challenge, "https://evil.example.net");
        assert_eq!(finish_registration(&rp(), &challenge, &other_origin, &object), Err(WebauthnError::Origin));
        let wrong_kind = client_data("webauthn.get", &challenge, &rp().origin);
        assert_eq!(finish_registration(&rp(), &challenge, &wrong_kind, &object), Err(WebauthnError::ClientData));
        let elsewhere = Relying { id: String::from("other.example.org"), origin: rp().origin };
        let fine = client_data("webauthn.create", &challenge, &rp().origin);
        assert_eq!(finish_registration(&elsewhere, &challenge, &fine, &object), Err(WebauthnError::RpHash));
        Ok(())
    }

    #[test]
    fn a_registration_without_user_presence_or_a_key_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let signing = key()?;
        let challenge = [7_u8; 32];
        let fine = client_data("webauthn.create", &challenge, &rp().origin);
        let absent = auth_data_for(&rp(), 0x44, 0, Some((&[9_u8; 16], &signing)))?;
        assert_eq!(finish_registration(&rp(), &challenge, &fine, &attestation(&absent)), Err(WebauthnError::Flags));
        let no_key = auth_data_for(&rp(), 0x01, 0, None)?;
        assert_eq!(finish_registration(&rp(), &challenge, &fine, &attestation(&no_key)), Err(WebauthnError::AuthData));
        Ok(())
    }

    #[test]
    fn an_assertion_verifies_and_the_counter_rises() -> Result<(), Box<dyn std::error::Error>> {
        let (signing, made) = registered()?;
        let challenge = [3_u8; 32];
        let (data, client, signature) = assertion(&signing, &challenge, 1, 0x01, &rp().origin)?;
        assert_eq!(finish_assertion(&rp(), &challenge, &made.public_key, 0, &data, &client, &signature)?, 1);
        let (data, client, signature) = assertion(&signing, &challenge, 1, 0x01, &rp().origin)?;
        assert_eq!(finish_assertion(&rp(), &challenge, &made.public_key, 1, &data, &client, &signature), Err(WebauthnError::Counter), "a replayed counter");
        Ok(())
    }

    #[test]
    fn an_authenticator_without_a_counter_stays_at_zero() -> Result<(), Box<dyn std::error::Error>> {
        let (signing, made) = registered()?;
        let challenge = [3_u8; 32];
        let (data, client, signature) = assertion(&signing, &challenge, 0, 0x01, &rp().origin)?;
        assert_eq!(finish_assertion(&rp(), &challenge, &made.public_key, 0, &data, &client, &signature)?, 0);
        Ok(())
    }

    #[test]
    fn a_forged_or_misdirected_assertion_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let (signing, made) = registered()?;
        let challenge = [3_u8; 32];
        let (data, client, mut signature) = assertion(&signing, &challenge, 1, 0x01, &rp().origin)?;
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(matches!(finish_assertion(&rp(), &challenge, &made.public_key, 0, &data, &client, &signature), Err(WebauthnError::Signature)));
        let stranger = key()?;
        let (data, client, signature) = assertion(&stranger, &challenge, 1, 0x01, &rp().origin)?;
        assert_eq!(finish_assertion(&rp(), &challenge, &made.public_key, 0, &data, &client, &signature), Err(WebauthnError::Signature), "another key");
        let (data, client, signature) = assertion(&signing, &challenge, 1, 0x01, "https://evil.example.net")?;
        assert_eq!(finish_assertion(&rp(), &challenge, &made.public_key, 0, &data, &client, &signature), Err(WebauthnError::Origin), "a phishing origin");
        let (data, client, signature) = assertion(&signing, &challenge, 1, 0x00, &rp().origin)?;
        assert_eq!(finish_assertion(&rp(), &challenge, &made.public_key, 0, &data, &client, &signature), Err(WebauthnError::Flags), "no user presence");
        let (data, client, signature) = assertion(&signing, &challenge, 1, 0x01, &rp().origin)?;
        assert_eq!(finish_assertion(&rp(), &[4_u8; 32], &made.public_key, 0, &data, &client, &signature), Err(WebauthnError::Challenge), "an old challenge");
        Ok(())
    }

    #[test]
    fn the_options_carry_the_name_the_keys_are_bound_to() {
        let made = registration_options(&rp(), &[1, 2], "alice", &[5; 32], &[vec![9; 16]]);
        assert_eq!(made["rp"]["id"], "console.example.org");
        assert_eq!(made["pubKeyCredParams"][0]["alg"], -7);
        assert_eq!(made["attestation"], "none");
        assert_eq!(made["excludeCredentials"].as_array().map(Vec::len), Some(1));
        let asked = assertion_options(&rp(), &[5; 32], &[vec![9; 16]]);
        assert_eq!(asked["rpId"], "console.example.org");
        assert_eq!(asked["allowCredentials"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn base64url_round_trips_and_refuses_padding() -> Result<(), WebauthnError> {
        assert_eq!(unb64(&b64(&[0xfb, 0xff, 0x01]))?, vec![0xfb, 0xff, 0x01]);
        assert_eq!(unb64("AQ=="), Err(WebauthnError::Encoding));
        Ok(())
    }
}
