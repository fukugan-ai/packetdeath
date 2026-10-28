//! The settings' HTTP road. `webapp/docs/design.ja.md`.
//!
//! A save is checked by the tool's own parser before anything is written. A
//! file with an unreadable line is refused as a whole, and the answer names
//! each line.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::app::{reader, writer, Fail, Reply, Shared};
use crate::settings::{SettingError, KINDS};
use crate::users::Role;

#[derive(Deserialize)]
pub struct Body {
    pub text: String,
}

fn setting_fail(error: SettingError) -> Fail {
    let status = match error {
        SettingError::Unknown => StatusCode::NOT_FOUND,
        SettingError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        SettingError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        SettingError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Fail(status, error.to_string())
}

/// The refusal of an unreadable file: the sentence and each line with its reason.
fn invalid(lines: &[(usize, String)]) -> Reply {
    let rows: Vec<_> = lines.iter().map(|(line, why)| json!({"line": line, "reason": why})).collect();
    let body = json!({"error": format!("{} line(s) cannot be read", lines.len()), "lines": rows});
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response())
}

pub async fn catalog(State(state): State<Shared>, headers: HeaderMap) -> Reply {
    reader(&state, &headers, Role::Viewer)?;
    let rows: Vec<_> = KINDS.iter().map(|k| json!({"id": k.id, "part": k.part, "file": k.file, "hot": k.hot})).collect();
    Ok(Json(json!({"settings": rows})).into_response())
}

pub async fn read(State(state): State<Shared>, headers: HeaderMap, Path(id): Path<String>) -> Reply {
    reader(&state, &headers, Role::Viewer)?;
    let text = state.settings.read(&id).map_err(setting_fail)?;
    Ok(Json(json!({"id": id, "text": text})).into_response())
}

pub async fn save(State(state): State<Shared>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<Body>) -> Reply {
    let me = writer(&state, &headers, Role::Operator)?;
    let saved = state.settings.save(&id, &body.text, state.now());
    let digests = match &saved {
        Ok(done) => (done.before.clone(), Some(done.after.clone())),
        Err(_) => (None, None),
    };
    if let Err(why) = state.audit.record(&me.name, "setting-save", &id, saved.is_ok(), digests) {
        eprintln!("webapp: the audit line was not written: {why}");
    }
    match saved {
        Ok(done) => Ok(Json(json!({"ok": true, "kept": done.kept, "digest": done.after})).into_response()),
        Err(SettingError::Invalid(lines)) => invalid(&lines),
        Err(other) => Err(setting_fail(other)),
    }
}
