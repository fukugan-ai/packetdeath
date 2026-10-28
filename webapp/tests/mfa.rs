//! PK-210 to PK-213 and PK-215: the second factor. TOTP codes are computed from the secret the console hands out.

mod common;

use axum::http::{Method, StatusCode};
use common::{login_of, rig, rig_requiring_mfa, Fault, Login, Rig, PASSWORD};
use packetdeath_webapp::totp::{code_at, secret_from_text, STEP_SECONDS};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

fn text_of<'a>(body: &'a Value, key: &str) -> Result<&'a str, Fault> {
    body[key].as_str().ok_or_else(|| format!("no {key} in {body}").into())
}

fn code_now(r: &Rig, secret: &str) -> Result<String, Fault> {
    let bytes = secret_from_text(secret).map_err(|e| format!("{e:?}"))?;
    let step = r.now.load(Ordering::SeqCst) / STEP_SECONDS;
    let code = code_at(&bytes, step).map_err(|e| format!("{e:?}"))?;
    Ok(format!("{code:06}"))
}

/// alice (an administrator) turns a second factor on; returns her secret and her recovery codes.
async fn enroll(r: &Rig, who: &Login) -> Result<(String, Vec<String>), Fault> {
    let begun = r.call(Method::POST, "/api/mfa/totp/begin", Some(who), true, None).await?;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.text);
    let secret = text_of(&begun.body()?, "secret")?.to_owned();
    let code = code_now(r, &secret)?;
    let done = r.call(Method::POST, "/api/mfa/totp/confirm", Some(who), true, Some(json!({"code": code}))).await?;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    let recovery = done.body()?["recovery"].as_array().ok_or("no recovery list")?.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect();
    // The code that turned the factor on is taken; the next sign-in needs the next step's code.
    r.advance(STEP_SECONDS);
    Ok((secret, recovery))
}

async fn password_step(r: &Rig) -> Result<String, Fault> {
    let reply = r.sign_in("alice", PASSWORD).await?;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert!(reply.headers.get("set-cookie").is_none(), "a cookie before the second step");
    assert_eq!(reply.body()?["mfa"], true);
    Ok(text_of(&reply.body()?, "ticket")?.to_owned())
}

#[tokio::test]
async fn pk210_a_secret_is_on_only_after_a_code_from_it_is_typed() -> Result<(), Fault> {
    let r = rig("pk210")?;
    let alice = r.register("alice").await?;
    let begun = r.call(Method::POST, "/api/mfa/totp/begin", Some(&alice), true, None).await?;
    let secret = text_of(&begun.body()?, "secret")?.to_owned();
    assert!(text_of(&begun.body()?, "uri")?.starts_with("otpauth://totp/"));
    assert_eq!(r.sign_in("alice", PASSWORD).await?.headers.get("set-cookie").is_some(), true, "pending secret must not gate sign-in");
    let wrong = r.call(Method::POST, "/api/mfa/totp/confirm", Some(&alice), true, Some(json!({"code": "000000"}))).await?;
    assert_eq!((wrong.status, wrong.body()?["code"].clone()), (StatusCode::UNPROCESSABLE_ENTITY, json!("PD_MFA_CODE")));
    let right = code_now(&r, &secret)?;
    let done = r.call(Method::POST, "/api/mfa/totp/confirm", Some(&alice), true, Some(json!({"code": right}))).await?;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text);
    assert_eq!(done.body()?["recovery"].as_array().map(Vec::len), Some(10));
    let again = r.call(Method::POST, "/api/mfa/totp/begin", Some(&alice), true, None).await?;
    assert_eq!((again.status, again.body()?["code"].clone()), (StatusCode::CONFLICT, json!("PD_MFA_ON")));
    Ok(())
}

#[tokio::test]
async fn pk211_a_right_password_alone_starts_no_session() -> Result<(), Fault> {
    let r = rig("pk211")?;
    let alice = r.register("alice").await?;
    let (secret, _) = enroll(&r, &alice).await?;
    let ticket = password_step(&r).await?;
    let none = r.call(Method::GET, "/api/users", None, false, None).await?;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    let wrong = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": "000000"}))).await?;
    assert_eq!((wrong.status, wrong.body()?["code"].clone()), (StatusCode::UNAUTHORIZED, json!("PD_AUTH_SECOND")));
    let right = code_now(&r, &secret)?;
    let through = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": right}))).await?;
    assert_eq!(through.status, StatusCode::OK, "{}", through.text);
    let me = login_of(&through)?;
    assert_eq!(r.call(Method::GET, "/api/users", Some(&me), false, None).await?.status, StatusCode::OK);
    let spent = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": code_now(&r, &secret)?}))).await?;
    assert_eq!((spent.status, spent.body()?["code"].clone()), (StatusCode::UNAUTHORIZED, json!("PD_AUTH_TICKET")));
    Ok(())
}

#[tokio::test]
async fn pk211_a_ticket_dies_at_the_fifth_wrong_code_and_with_time() -> Result<(), Fault> {
    let r = rig("pk211-ticket")?;
    let alice = r.register("alice").await?;
    let (secret, _) = enroll(&r, &alice).await?;
    let fresh = password_step(&r).await?;
    r.advance(301);
    let old = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": fresh, "code": code_now(&r, &secret)?}))).await?;
    assert_eq!(old.body()?["code"], "PD_AUTH_TICKET", "a ticket outlived five minutes");
    let ticket = password_step(&r).await?;
    for _ in 0..5 {
        let miss = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": "000000"}))).await?;
        assert_eq!(miss.status, StatusCode::UNAUTHORIZED);
    }
    let right = code_now(&r, &secret)?;
    let late = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": right}))).await?;
    assert!(matches!(late.body()?["code"].as_str(), Some("PD_AUTH_TICKET" | "PD_AUTH_LIMITED")), "the fifth miss should have shut the second step: {}", late.text);
    Ok(())
}

#[tokio::test]
async fn pk212_a_code_is_taken_once_and_only_near_its_step() -> Result<(), Fault> {
    let r = rig("pk212")?;
    let alice = r.register("alice").await?;
    let (secret, _) = enroll(&r, &alice).await?;
    r.advance(STEP_SECONDS);
    let used = code_now(&r, &secret)?;
    let first = password_step(&r).await?;
    let ok = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": first, "code": used}))).await?;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    let second = password_step(&r).await?;
    let replay = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": second, "code": used}))).await?;
    assert_eq!(replay.body()?["code"], "PD_AUTH_SECOND", "the same code twice");
    r.advance(5 * STEP_SECONDS);
    let far = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": second, "code": used}))).await?;
    assert_eq!(far.status, StatusCode::UNAUTHORIZED, "a code five steps old");
    Ok(())
}

#[tokio::test]
async fn pk213_a_recovery_code_works_once_and_is_not_stored_as_text() -> Result<(), Fault> {
    let r = rig("pk213")?;
    let alice = r.register("alice").await?;
    let (_, recovery) = enroll(&r, &alice).await?;
    assert_eq!(recovery.len(), 10);
    let file = std::fs::read_to_string(r.dir.join("data").join("users.json"))?;
    for code in &recovery {
        assert_eq!(file.matches(code.as_str()).count(), 0, "a recovery code is in the file as text");
    }
    let first = recovery.first().ok_or("no recovery code")?;
    let ticket = password_step(&r).await?;
    let ok = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": ticket, "code": first.to_lowercase()}))).await?;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    let again = password_step(&r).await?;
    let twice = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": again, "code": first}))).await?;
    assert_eq!(twice.body()?["code"], "PD_AUTH_SECOND", "a recovery code worked twice");
    let other = recovery.get(1).ok_or("no second recovery code")?;
    let third = r.call(Method::POST, "/api/login/second", None, false, Some(json!({"ticket": again, "code": other}))).await?;
    assert_eq!(third.status, StatusCode::OK, "{}", third.text);
    Ok(())
}

#[tokio::test]
async fn pk215_an_administrator_without_a_second_factor_changes_nothing() -> Result<(), Fault> {
    let r = rig_requiring_mfa("pk215")?;
    let alice = r.register("alice").await?;
    let body = || Some(json!({"text": "192.0.2.1\n"}));
    let refused = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&alice), true, body()).await?;
    assert_eq!((refused.status, refused.body()?["code"].clone()), (StatusCode::FORBIDDEN, json!("PD_AUTH_MFA_REQUIRED")));
    let users = r.call(Method::POST, "/api/users", Some(&alice), true, Some(json!({"name": "x", "password": PASSWORD, "role": "viewer"}))).await?;
    assert_eq!(users.body()?["code"], "PD_AUTH_MFA_REQUIRED");
    assert_eq!(r.call(Method::GET, "/api/settings", Some(&alice), false, None).await?.status, StatusCode::OK, "reading must stay open");
    enroll(&r, &alice).await?;
    let allowed = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&alice), true, body()).await?;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text);
    Ok(())
}

#[tokio::test]
async fn an_administrator_can_remove_a_lost_second_factor() -> Result<(), Fault> {
    let r = rig("mfa-reset")?;
    let alice = r.register("alice").await?;
    let otto = r.user_with(&alice, "otto", "operator").await?;
    enroll(&r, &otto).await?;
    assert_eq!(r.sign_in("otto", PASSWORD).await?.body()?["mfa"], true);
    let reset = r.call(Method::PATCH, "/api/users/otto", Some(&alice), true, Some(json!({"mfa_reset": true}))).await?;
    assert_eq!(reset.status, StatusCode::OK, "{}", reset.text);
    assert!(r.sign_in("otto", PASSWORD).await?.headers.get("set-cookie").is_some(), "the second factor was not removed");
    Ok(())
}
