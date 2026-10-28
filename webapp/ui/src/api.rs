//! A thin fetch wrapper. `webapp/docs/design.ja.md`.
//!
//! Every call goes to the page's own origin and carries the session cookie.
//! A change carries the CSRF token the sign-in answered with.

use gloo_net::http::{Request, RequestBuilder};
use serde_json::Value;
use web_sys::RequestCredentials;

/// A line the tool's parser cannot read.
#[derive(Clone, Debug, PartialEq)]
pub struct BadLine {
    pub line: u64,
    pub reason: String,
}

/// Why a call did not give an answer to show.
#[derive(Clone, Debug, PartialEq)]
pub struct ApiError {
    pub status: u16,
    /// The server's `PD_<PART>_<REASON>`; `PD_HTTP_<status>` when the answer carried none (a framework refusal), `PD_UI_NETWORK` when no answer came.
    pub code: String,
    pub message: String,
    pub lines: Vec<BadLine>,
}

impl ApiError {
    fn network() -> Self {
        Self { status: 0, code: String::from("PD_UI_NETWORK"), message: String::from("network"), lines: Vec::new() }
    }

    pub fn is_signed_out(&self) -> bool {
        self.status == 401
    }
}

fn lines_of(body: &Value) -> Vec<BadLine> {
    let Some(rows) = body.get("lines").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for row in rows {
        let line = row.get("line").and_then(Value::as_u64);
        let reason = row.get("reason").and_then(Value::as_str);
        if let (Some(line), Some(reason)) = (line, reason) {
            found.push(BadLine { line, reason: reason.to_owned() });
        }
    }
    found
}

async fn finish(builder: Result<Request, gloo_net::Error>) -> Result<Value, ApiError> {
    let request = builder.map_err(|_| ApiError::network())?;
    let response = request.send().await.map_err(|_| ApiError::network())?;
    let status = response.status();
    let text = response.text().await.map_err(|_| ApiError::network())?;
    // An answer that is not JSON (an empty body) is an answer with no fields; the status decides.
    let body = serde_json::from_str::<Value>(&text).ok();
    if (200..300).contains(&status) {
        return body.ok_or(ApiError { status, code: String::from("PD_UI_NOT_JSON"), message: String::from("not json"), lines: Vec::new() });
    }
    // An answer with no fields of ours (a framework refusal such as a missing JSON field) keeps the status as its code and the text as its sentence.
    let (mut code, mut message, mut lines) = (format!("PD_HTTP_{status}"), text.clone(), Vec::new());
    if let Some(body) = &body {
        if let Some(found) = body.get("error").and_then(Value::as_str) {
            message = found.to_owned();
        }
        if let Some(found) = body.get("code").and_then(Value::as_str) {
            code = found.to_owned();
        }
        lines = lines_of(body);
    }
    Err(ApiError { status, code, message, lines })
}

fn with_cookie(builder: RequestBuilder) -> RequestBuilder {
    builder.credentials(RequestCredentials::SameOrigin)
}

pub async fn get(path: &str) -> Result<Value, ApiError> {
    finish(with_cookie(Request::get(path)).build()).await
}

/// A change: `method` is one of POST, PUT, PATCH, DELETE.
pub async fn send(method: &str, path: &str, csrf: &str, body: &Value) -> Result<Value, ApiError> {
    let builder = match method {
        "PUT" => Request::put(path),
        "PATCH" => Request::patch(path),
        "DELETE" => Request::delete(path),
        _ => Request::post(path),
    };
    let with_headers = with_cookie(builder).header("X-CSRF-Token", csrf);
    finish(with_headers.json(body)).await
}
