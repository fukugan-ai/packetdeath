//! PK-214: a passkey is bound to the console's name, signs a fresh challenge, and its counter must rise.
//! A software authenticator (a P-256 key) plays the browser's part.

mod common;

use axum::http::{Method, StatusCode};
use common::{login_of, relying, rig, rig_with_passkeys, Fault, Login, Rig, PASSWORD};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use packetdeath_webapp::webauthn::{b64, unb64};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn text_of<'a>(body: &'a Value, key: &str) -> Result<&'a str, Fault> {
    body[key].as_str().ok_or_else(|| format!("no {key} in {body}").into())
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

/// The browser's part: a key, and the answers it gives.
struct Authenticator {
    key: SigningKey,
    id: Vec<u8>,
}

impl Authenticator {
    fn new() -> Result<Self, Fault> {
        let (mut seed, mut id) = ([0_u8; 32], vec![0_u8; 16]);
        getrandom::fill(&mut seed)?;
        getrandom::fill(&mut id)?;
        Ok(Self { key: SigningKey::from_slice(&seed)?, id })
    }

    fn rp_hash() -> Vec<u8> {
        Sha256::digest(relying().id.as_bytes()).to_vec()
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": challenge, "origin": origin}).to_string().into_bytes()
    }

    /// The body of `/api/mfa/webauthn/finish` for the challenge the console issued.
    fn created(&self, challenge: &str, origin: &str) -> Result<Value, Fault> {
        let mut data = Self::rp_hash();
        data.push(0x45);
        data.extend_from_slice(&0_u32.to_be_bytes());
        data.extend_from_slice(&[0_u8; 16]);
        data.extend_from_slice(&u16::try_from(self.id.len())?.to_be_bytes());
        data.extend_from_slice(&self.id);
        let point = self.key.verifying_key().to_sec1_bytes();
        data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        data.extend_from_slice(point.get(1..33).ok_or("no x")?);
        data.extend_from_slice(&[0x22, 0x58, 0x20]);
        data.extend_from_slice(point.get(33..65).ok_or("no y")?);
        let mut object = vec![0xa3];
        object.extend(cbor_text("fmt"));
        object.extend(cbor_text("none"));
        object.extend(cbor_text("attStmt"));
        object.push(0xa0);
        object.extend(cbor_text("authData"));
        object.extend(cbor_bytes(&data));
        Ok(json!({"clientDataJSON": b64(&Self::client_data("webauthn.create", challenge, origin)), "attestationObject": b64(&object)}))
    }

    /// The body of `/api/login/webauthn/finish`.
    fn signed(&self, ticket: &str, challenge: &str, origin: &str, count: u32) -> Value {
        let mut data = Self::rp_hash();
        data.push(0x01);
        data.extend_from_slice(&count.to_be_bytes());
        let client = Self::client_data("webauthn.get", challenge, origin);
        let mut message = data.clone();
        message.extend_from_slice(&Sha256::digest(&client));
        let signature: Signature = self.key.sign(&message);
        json!({
            "ticket": ticket,
            "id": b64(&self.id),
            "authenticatorData": b64(&data),
            "clientDataJSON": b64(&client),
            "signature": b64(signature.to_der().as_bytes()),
        })
    }
}

async fn add_passkey(r: &Rig, who: &Login, key: &Authenticator) -> Result<Value, Fault> {
    let begun = r.call(Method::POST, "/api/mfa/webauthn/begin", Some(who), true, None).await?;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let challenge = text_of(&begun.body()?, "challenge")?.to_owned();
    assert_eq!(begun.body()?["rp"]["id"], relying().id.as_str());
    let done = r.call(Method::POST, "/api/mfa/webauthn/finish", Some(who), true, Some(key.created(&challenge, &relying().origin)?)).await?;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    done.body()
}

/// Password step, then the passkey options: the ticket and the challenge.
async fn ask(r: &Rig) -> Result<(String, String), Fault> {
    let first = r.sign_in("alice", PASSWORD).await?;
    assert_eq!(first.body()?["webauthn"], true, "{}", first.text);
    assert_eq!(first.body()?["totp"], false);
    assert!(first.headers.get("set-cookie").is_none(), "a cookie before the second step");
    let ticket = text_of(&first.body()?, "ticket")?.to_owned();
    let options = r.call(Method::POST, "/api/login/webauthn/begin", None, false, Some(json!({"ticket": ticket}))).await?;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text);
    let challenge = text_of(&options.body()?, "challenge")?.to_owned();
    Ok((ticket, challenge))
}

#[tokio::test]
async fn pk214_a_passkey_is_added_and_signs_in_and_the_counter_must_rise() -> Result<(), Fault> {
    let r = rig_with_passkeys("pk214")?;
    let alice = r.register("alice").await?;
    let key = Authenticator::new()?;
    let added = add_passkey(&r, &alice, &key).await?;
    assert_eq!(added["recovery"].as_array().map(Vec::len), Some(10), "the first factor brings the recovery codes");

    let (ticket, challenge) = ask(&r).await?;
    let through = r.call(Method::POST, "/api/login/webauthn/finish", None, false, Some(key.signed(&ticket, &challenge, &relying().origin, 1))).await?;
    assert_eq!(through.status, StatusCode::OK, "{}", through.text);
    let me = login_of(&through)?;
    assert_eq!(r.call(Method::GET, "/api/users", Some(&me), false, None).await?.status, StatusCode::OK);

    let (ticket, challenge) = ask(&r).await?;
    let replay = r.call(Method::POST, "/api/login/webauthn/finish", None, false, Some(key.signed(&ticket, &challenge, &relying().origin, 1))).await?;
    assert_eq!((replay.status, replay.body()?["code"].clone()), (StatusCode::UNAUTHORIZED, json!("PD_AUTH_SECOND")), "a counter that did not rise");
    Ok(())
}

#[tokio::test]
async fn pk214_a_recovery_code_signs_in_a_user_who_has_only_a_passkey() -> Result<(), Fault> {
    let r = rig_with_passkeys("pk214-recovery")?;
    let alice = r.register("alice").await?;
    let key = Authenticator::new()?;
    let added = add_passkey(&r, &alice, &key).await?;
    let code = text_of(&json!({"c": added["recovery"][0]}), "c")?.to_owned();

    let (ticket, _) = ask(&r).await?;
    let wrong = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": "000000"}))).await?;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.text);
    let through = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": code}))).await?;
    assert_eq!(through.status, StatusCode::OK, "{}", through.text);

    let (again, _) = ask(&r).await?;
    let spent = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": again, "code": code}))).await?;
    assert_eq!(spent.status, StatusCode::UNAUTHORIZED, "a recovery code works once");
    Ok(())
}

#[tokio::test]
async fn pk214_a_phishing_origin_a_stranger_key_and_an_old_challenge_are_refused() -> Result<(), Fault> {
    let r = rig_with_passkeys("pk214-refuse")?;
    let alice = r.register("alice").await?;
    let key = Authenticator::new()?;
    add_passkey(&r, &alice, &key).await?;

    let (ticket, challenge) = ask(&r).await?;
    let phishing = r.call(Method::POST, "/api/login/webauthn/finish", None, false, Some(key.signed(&ticket, &challenge, "https://evil.example.net", 1))).await?;
    assert_eq!(phishing.body()?["code"], "PD_AUTH_SECOND", "{}", phishing.text);

    let (ticket, challenge) = ask(&r).await?;
    let stranger = Authenticator::new()?;
    let forged = stranger.signed(&ticket, &challenge, &relying().origin, 1);
    let miss = r.call(Method::POST, "/api/login/webauthn/finish", None, false, Some(forged)).await?;
    assert_eq!(miss.body()?["code"], "PD_AUTH_SECOND", "a key that was never added");

    let (ticket, challenge) = ask(&r).await?;
    let first = r.call(Method::POST, "/api/login/webauthn/finish", None, false, Some(key.signed(&ticket, &challenge, &relying().origin, 1))).await?;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let again = r.call(Method::POST, "/api/login/webauthn/finish", None, false, Some(key.signed(&ticket, &challenge, &relying().origin, 2))).await?;
    assert_eq!(again.body()?["code"], "PD_AUTH_TICKET", "a ticket and its challenge are used once");
    Ok(())
}

#[tokio::test]
async fn pk214_a_registration_for_another_challenge_is_refused() -> Result<(), Fault> {
    let r = rig_with_passkeys("pk214-register")?;
    let alice = r.register("alice").await?;
    let key = Authenticator::new()?;
    let begun = r.call(Method::POST, "/api/mfa/webauthn/begin", Some(&alice), true, None).await?;
    assert_eq!(begun.status, StatusCode::OK);
    let wrong = b64(&[1_u8; 32]);
    let refused = r.call(Method::POST, "/api/mfa/webauthn/finish", Some(&alice), true, Some(key.created(&wrong, &relying().origin)?)).await?;
    assert_eq!((refused.status, refused.body()?["code"].clone()), (StatusCode::UNPROCESSABLE_ENTITY, json!("PD_MFA_PASSKEY")));
    let spent = r.call(Method::POST, "/api/mfa/webauthn/finish", Some(&alice), true, Some(key.created(&wrong, &relying().origin)?)).await?;
    assert_eq!(spent.body()?["code"], "PD_MFA_PASSKEY_CHALLENGE", "the challenge is used once, right or wrong");
    assert!(unb64(&wrong).is_ok());
    Ok(())
}

#[tokio::test]
async fn pk214_passkeys_are_off_without_a_name() -> Result<(), Fault> {
    let r = rig("pk214-off")?;
    let alice = r.register("alice").await?;
    let off = r.call(Method::POST, "/api/mfa/webauthn/begin", Some(&alice), true, None).await?;
    assert_eq!((off.status, off.body()?["code"].clone()), (StatusCode::NOT_FOUND, json!("PD_MFA_PASSKEY_OFF")));
    Ok(())
}
