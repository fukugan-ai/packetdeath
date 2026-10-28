//! Health, status and the screens' static files. `webapp/docs/design.ja.md`.

use std::path::{Component, Path as FsPath, PathBuf};

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Json;

use crate::app::{reader, Fail, Reply, Shared};
use crate::status;
use crate::users::Role;

pub async fn health() -> &'static str {
    "ok"
}

pub async fn status(State(state): State<Shared>, headers: HeaderMap) -> Reply {
    reader(&state, &headers, Role::Viewer)?;
    let found = status::read(&state.log_dir).map_err(|why| Fail(StatusCode::INTERNAL_SERVER_ERROR, "PD_STATUS_READ", why))?;
    Ok(Json(found).into_response())
}

/// The kind of a file by its extension; a file of another kind is not served.
fn content_type(path: &FsPath) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "html" => Some("text/html; charset=utf-8"),
        "js" => Some("text/javascript"),
        "wasm" => Some("application/wasm"),
        "css" => Some("text/css"),
        "svg" => Some("image/svg+xml"),
        "png" => Some("image/png"),
        "ico" => Some("image/x-icon"),
        "json" => Some("application/json"),
        _ => None,
    }
}

/// The file under `root` that `uri` names, or None for a path with `..`, a root or a prefix in it.
fn resolve(root: &FsPath, uri: &Uri) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    for part in FsPath::new(uri.path().trim_start_matches('/')).components() {
        match part {
            Component::Normal(name) => rel.push(name),
            _ => return None,
        }
    }
    if rel.as_os_str().is_empty() {
        rel.push("index.html");
    }
    Some(root.join(rel))
}

pub async fn file(State(state): State<Shared>, uri: Uri) -> Reply {
    let missing = || Fail(StatusCode::NOT_FOUND, "PD_PAGE_NOT_FOUND", String::from("not found"));
    let root = state.static_dir.as_ref().ok_or_else(missing)?;
    let path = resolve(root, &uri).ok_or_else(missing)?;
    let kind = content_type(&path).ok_or_else(missing)?;
    let bytes = std::fs::read(&path).map_err(|_| missing())?;
    Ok(([(CONTENT_TYPE, kind)], bytes).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_the_index_page() -> Result<(), Box<dyn std::error::Error>> {
        let found = resolve(FsPath::new("/srv"), &"/".parse::<Uri>()?);
        assert_eq!(found, Some(PathBuf::from("/srv/index.html")));
        Ok(())
    }

    #[test]
    fn a_path_that_climbs_out_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(resolve(FsPath::new("/srv"), &"/a/../../etc/passwd".parse::<Uri>()?), None);
        assert_eq!(resolve(FsPath::new("/srv"), &"/..".parse::<Uri>()?), None);
        Ok(())
    }

    #[test]
    fn only_known_kinds_are_served() {
        assert!(content_type(FsPath::new("app.wasm")).is_some());
        assert!(content_type(FsPath::new("users.json.bak")).is_none());
        assert!(content_type(FsPath::new("noext")).is_none());
    }
}
