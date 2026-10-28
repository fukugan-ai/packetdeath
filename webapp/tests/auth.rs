//! PK-190 to PK-193 and PK-199: who may sign in, who may change what, and who may manage users.

mod common;

use axum::http::{Method, StatusCode};
use common::{login_of, rig, Fault, Login, PASSWORD};
use serde_json::json;

#[tokio::test]
async fn pk190_only_the_first_registration_makes_an_administrator() -> Result<(), Fault> {
    let r = rig("pk190")?;
    let before = r.call(Method::GET, "/api/bootstrap", None, false, None).await?;
    assert_eq!(before.body()?["needs_register"], true);
    let first = r.register("alice").await?;
    let after = r.call(Method::GET, "/api/bootstrap", Some(&first), false, None).await?;
    assert_eq!(after.body()?["needs_register"], false);
    assert_eq!(after.body()?["me"]["role"], "admin");
    let second = r.call(Method::POST, "/api/register", None, false, Some(json!({"name": "mallory", "password": PASSWORD}))).await?;
    assert_eq!(second.status, StatusCode::CONFLICT);
    let sneaky = r.sign_in("mallory", PASSWORD).await?;
    assert_eq!(sneaky.status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn pk191_the_file_holds_a_hash_and_a_wrong_answer_is_the_same_for_every_account() -> Result<(), Fault> {
    let r = rig("pk191")?;
    r.register("alice").await?;
    let file = std::fs::read_to_string(r.dir.join("data").join("users.json"))?;
    assert!(file.contains("$argon2id$"), "no argon2id hash in the file");
    assert_eq!(file.matches(PASSWORD).count(), 0, "the password is in the file");
    let wrong = r.sign_in("alice", "not the password at all").await?;
    let unknown = r.sign_in("nobody", "not the password at all").await?;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!((wrong.status, wrong.text.as_str()), (unknown.status, unknown.text.as_str()));
    assert!(wrong.headers.get("set-cookie").is_none());
    Ok(())
}

#[tokio::test]
async fn pk192_a_change_needs_a_session_a_csrf_token_and_a_role() -> Result<(), Fault> {
    let r = rig("pk192")?;
    let admin = r.register("alice").await?;
    let viewer = r.user_with(&admin, "vera", "viewer").await?;
    let operator = r.user_with(&admin, "otto", "operator").await?;
    let body = || Some(json!({"text": "192.0.2.1\n"}));
    let none = r.call(Method::PUT, "/api/settings/waf-allow-ip", None, false, body()).await?;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    let read_none = r.call(Method::GET, "/api/settings", None, false, None).await?;
    assert_eq!(read_none.status, StatusCode::UNAUTHORIZED);
    let no_csrf = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&operator), false, body()).await?;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
    let forged = Login { cookie: operator.cookie.clone(), csrf: viewer.csrf.clone() };
    let wrong_token = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&forged), true, body()).await?;
    assert_eq!(wrong_token.status, StatusCode::FORBIDDEN);
    let as_viewer = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&viewer), true, body()).await?;
    assert_eq!(as_viewer.status, StatusCode::FORBIDDEN);
    let reading = r.call(Method::GET, "/api/settings/waf-allow-ip", Some(&viewer), false, None).await?;
    assert_eq!(reading.status, StatusCode::OK);
    let as_operator = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&operator), true, body()).await?;
    assert_eq!(as_operator.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn pk192_a_neighbour_cookie_with_a_byte_above_ascii_does_not_sign_the_user_out() -> Result<(), Fault> {
    let r = rig("pk192-cookie")?;
    let admin = r.register("alice").await?;
    let crowded = Login { cookie: format!("theme=caf\u{e9}; {}; other=1", admin.cookie), csrf: admin.csrf.clone() };
    let reply = r.call(Method::GET, "/api/users", Some(&crowded), false, None).await?;
    assert_eq!(reply.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn pk193_five_failures_make_the_account_wait_until_the_time_passes() -> Result<(), Fault> {
    let r = rig("pk193")?;
    r.register("alice").await?;
    for _ in 0..5 {
        let miss = r.sign_in("alice", "wrong wrong wrong").await?;
        assert_eq!(miss.status, StatusCode::UNAUTHORIZED);
    }
    let waiting = r.sign_in("alice", PASSWORD).await?;
    assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
    r.advance(14 * 60);
    assert_eq!(r.sign_in("alice", PASSWORD).await?.status, StatusCode::TOO_MANY_REQUESTS);
    r.advance(2 * 60);
    let through = r.sign_in("alice", PASSWORD).await?;
    assert_eq!(through.status, StatusCode::OK);
    login_of(&through)?;
    Ok(())
}

#[tokio::test]
async fn pk199_only_an_administrator_manages_users_and_the_last_one_stays() -> Result<(), Fault> {
    let r = rig("pk199")?;
    let admin = r.register("alice").await?;
    let operator = r.user_with(&admin, "otto", "operator").await?;
    let listed = r.call(Method::GET, "/api/users", Some(&operator), false, None).await?;
    assert_eq!(listed.status, StatusCode::FORBIDDEN);
    let denied = r.call(Method::POST, "/api/users", Some(&operator), true, Some(json!({"name": "x", "password": PASSWORD, "role": "admin"}))).await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let promote = r.call(Method::PATCH, "/api/users/otto", Some(&admin), true, Some(json!({"role": "viewer"}))).await?;
    assert_eq!(promote.status, StatusCode::OK);
    let now_viewer = r.call(Method::PUT, "/api/settings/waf-allow-ip", Some(&operator), true, Some(json!({"text": "192.0.2.1\n"}))).await?;
    assert_eq!(now_viewer.status, StatusCode::FORBIDDEN, "the role change did not reach the open session");

    let off = r.call(Method::PATCH, "/api/users/otto", Some(&admin), true, Some(json!({"disabled": true}))).await?;
    assert_eq!(off.status, StatusCode::OK);
    assert_eq!(r.sign_in("otto", PASSWORD).await?.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.call(Method::GET, "/api/settings", Some(&operator), false, None).await?.status, StatusCode::UNAUTHORIZED);

    let reset = r.call(Method::PATCH, "/api/users/otto", Some(&admin), true, Some(json!({"disabled": false, "password": "a brand new password"}))).await?;
    assert_eq!(reset.status, StatusCode::OK);
    assert_eq!(r.sign_in("otto", PASSWORD).await?.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.sign_in("otto", "a brand new password").await?.status, StatusCode::OK);

    for attempt in [
        r.call(Method::DELETE, "/api/users/alice", Some(&admin), true, None).await?,
        r.call(Method::PATCH, "/api/users/alice", Some(&admin), true, Some(json!({"role": "viewer"}))).await?,
        r.call(Method::PATCH, "/api/users/alice", Some(&admin), true, Some(json!({"disabled": true}))).await?,
    ] {
        assert_eq!(attempt.status, StatusCode::CONFLICT, "{}", attempt.text);
    }
    let gone = r.call(Method::DELETE, "/api/users/otto", Some(&admin), true, None).await?;
    assert_eq!(gone.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn signing_out_ends_the_session() -> Result<(), Fault> {
    let r = rig("logout")?;
    let admin = r.register("alice").await?;
    let out = r.call(Method::POST, "/api/logout", Some(&admin), true, None).await?;
    assert_eq!(out.status, StatusCode::OK);
    let after = r.call(Method::GET, "/api/users", Some(&admin), false, None).await?;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    Ok(())
}
