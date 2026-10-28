//! PK-194 to PK-197: saving the settings through the HTTP road.

mod common;

use std::path::Path;
use std::sync::atomic::Ordering;

use axum::http::{Method, StatusCode};
use common::{rig, Fault, Login, Rig};
use serde_json::json;

const RULE: &str = r#"{"id":990001,"target":"query","pattern":"forbidden-word","severity":"critical","paranoia":1,"message":"mine"}"#;
const EXCLUSION: &str = r#"{"rule":942100,"path_prefix":"/search"}"#;

async fn operator(r: &Rig) -> Result<Login, Fault> {
    let admin = r.register("alice").await?;
    r.user_with(&admin, "otto", "operator").await
}

async fn put(r: &Rig, who: &Login, id: &str, text: &str) -> Result<common::Reply, Fault> {
    r.call(Method::PUT, &format!("/api/settings/{id}"), Some(who), true, Some(json!({"text": text}))).await
}

fn policy_sample() -> Result<String, Fault> {
    Ok(std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/ids/policy.jsonl"))?)
}

#[tokio::test]
async fn pk194_an_unreadable_policy_line_is_named_and_a_good_one_replaces_the_file_and_keeps_the_old() -> Result<(), Fault> {
    let r = rig("pk194")?;
    let who = operator(&r).await?;
    let good = policy_sample()?;
    assert_eq!(put(&r, &who, "ips-policy", &good).await?.status, StatusCode::OK);
    let broken = format!("{good}this is not json\n");
    let refused = put(&r, &who, "ips-policy", &broken).await?;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = refused.body()?;
    let first = &body["lines"][0];
    assert_eq!(first["line"], good.lines().count() + 1);
    assert!(first["reason"].as_str().is_some_and(|why| !why.is_empty()));
    assert_eq!(std::fs::read_to_string(r.dir.join("config").join("ips-policy.jsonl"))?, good, "a refused save changed the file");

    r.advance(5);
    let changed = format!("{good}\n# a note\n");
    let saved = put(&r, &who, "ips-policy", &changed).await?;
    assert_eq!(saved.status, StatusCode::OK);
    let kept = saved.body()?["kept"].as_str().map(str::to_owned);
    let Some(kept) = kept else {
        return Err("the answer names no kept version".into());
    };
    assert_eq!(std::fs::read_to_string(r.dir.join("config").join("backups").join(&kept))?, good);
    let shown = r.call(Method::GET, "/api/settings/ips-policy", Some(&who), false, None).await?;
    assert_eq!(shown.body()?["text"], changed);
    Ok(())
}

#[tokio::test]
async fn pk195_every_kind_saves_through_the_same_road() -> Result<(), Fault> {
    let r = rig("pk195")?;
    let who = operator(&r).await?;
    let policy = policy_sample()?;
    let samples: [(&str, String); 12] = [
        ("ips-policy", policy),
        ("ips-never", String::from("192.0.2.1\n")),
        ("ids-sids", String::from("9000001\n")),
        ("waf-rules", format!("{RULE}\n")),
        ("waf-exclusions", format!("{EXCLUSION}\n")),
        ("waf-allow-ip", String::from("192.0.2.0/24\n")),
        ("waf-deny-ip", String::from("198.51.100.7\n")),
        ("waf-trusted", String::from("203.0.113.1\n")),
        ("blocklist", String::from("ads.example\n")),
        ("allowlist", String::from("good.example\n")),
        ("iplist", String::from("192.0.2.9\n")),
        ("mitm-list", String::from("scan.example\n")),
    ];
    let catalog = r.call(Method::GET, "/api/settings", Some(&who), false, None).await?;
    assert_eq!(catalog.body()?["settings"].as_array().map(Vec::len), Some(samples.len()));
    for (id, text) in &samples {
        let saved = put(&r, &who, id, text).await?;
        assert_eq!(saved.status, StatusCode::OK, "{id}: {}", saved.text);
        let back = r.call(Method::GET, &format!("/api/settings/{id}"), Some(&who), false, None).await?;
        assert_eq!(back.body()?["text"].as_str(), Some(text.as_str()), "{id}");
    }
    let unknown = put(&r, &who, "nothing", "x").await?;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let bad_host = put(&r, &who, "blocklist", "bad host!\n").await?;
    assert_eq!(bad_host.status, StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}

#[tokio::test]
async fn pk196_a_crash_before_the_rename_leaves_the_original_whole() -> Result<(), Fault> {
    let r = rig("pk196")?;
    let who = operator(&r).await?;
    assert_eq!(put(&r, &who, "ids-sids", "9000001\n").await?.status, StatusCode::OK);
    let path = r.dir.join("config").join("ids-sids.txt");
    let before = std::fs::read(&path)?;
    r.state.settings.crash_before_rename.store(true, Ordering::SeqCst);
    let crashed = put(&r, &who, "ids-sids", "9000002\n").await?;
    assert_eq!(crashed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(std::fs::read(&path)?, before, "the original changed");
    r.state.settings.crash_before_rename.store(false, Ordering::SeqCst);
    assert_eq!(put(&r, &who, "ids-sids", "9000002\n").await?.status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn pk197_the_audit_keeps_digests_and_no_password_and_no_setting_text() -> Result<(), Fault> {
    let r = rig("pk197")?;
    let who = operator(&r).await?;
    let secret_line = "192.0.2.77";
    assert_eq!(put(&r, &who, "waf-deny-ip", &format!("{secret_line}\n")).await?.status, StatusCode::OK);
    assert_eq!(put(&r, &who, "waf-deny-ip", "not an address\n").await?.status, StatusCode::UNPROCESSABLE_ENTITY);
    let log = std::fs::read_to_string(r.dir.join("data").join("webapp.jsonl"))?;
    assert!(log.contains("setting-save"), "no save line");
    assert!(log.contains("user-create"), "no user line");
    assert!(log.contains("\"ok\":false"), "the refused save left no line");
    assert_eq!(log.matches(common::PASSWORD).count(), 0);
    assert_eq!(log.matches(secret_line).count(), 0);
    for line in log.lines() {
        serde_json::from_str::<serde_json::Value>(line)?;
    }
    Ok(())
}
