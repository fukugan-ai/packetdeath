//! PK-198: the status road returns the numbers `waf-report` and `ips-report` print.

mod common;

use std::path::Path;

use axum::http::{Method, StatusCode};
use common::{rig, Fault};
use packetdeath::ips::report as ips;
use packetdeath::waf::report as waf;

#[tokio::test]
async fn pk198_the_status_equals_the_command_line_reports() -> Result<(), Fault> {
    let r = rig("pk198")?;
    let admin = r.register("alice").await?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let waf_text = std::fs::read_to_string(root.join("tests/waf/fixture-log/waf.jsonl"))?;
    let ips_text = std::fs::read_to_string(root.join("tests/ids/fixture-log/ips.jsonl"))?;
    std::fs::write(r.dir.join("logs").join("waf.jsonl"), &waf_text)?;
    std::fs::write(r.dir.join("logs").join("ips.jsonl"), &ips_text)?;
    let reply = r.call(Method::GET, "/api/status", Some(&admin), false, None).await?;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.body()?;
    assert_eq!(body["waf"]["total"], waf::summarize(&waf_text, None).total);
    assert_eq!(body["ips"]["lines"], ips::summarize(&ips_text, None).lines);
    assert_eq!(body["waf"]["total"], 10);
    assert_eq!(body["ips"]["events"]["drop"], 2);
    Ok(())
}

#[tokio::test]
async fn pk198_a_log_that_does_not_exist_yet_is_absent_and_a_session_is_needed() -> Result<(), Fault> {
    let r = rig("pk198-absent")?;
    let anonymous = r.call(Method::GET, "/api/status", None, false, None).await?;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let admin = r.register("alice").await?;
    let reply = r.call(Method::GET, "/api/status", Some(&admin), false, None).await?;
    assert_eq!(reply.body()?["waf"]["present"], false);
    assert_eq!(reply.body()?["ips"]["present"], false);
    Ok(())
}

#[tokio::test]
async fn the_health_check_needs_no_session() -> Result<(), Fault> {
    let r = rig("health")?;
    let reply = r.call(Method::GET, "/healthz", None, false, None).await?;
    assert_eq!((reply.status, reply.text.as_str()), (StatusCode::OK, "ok"));
    assert!(reply.headers.get("x-content-type-options").is_some());
    Ok(())
}
