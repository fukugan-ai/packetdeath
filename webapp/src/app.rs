//! The server's shared state, its guards and its router. `webapp/docs/design.ja.md`.
//!
//! Every request passes the same three questions here and nowhere else: is
//! there a live session, does a change carry the session's CSRF token, and is
//! the role high enough. A handler asks one of `reader` and `writer` first and
//! does nothing before that answer.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::extract::{ConnectInfo, Request};
use axum::http::header::{CONTENT_SECURITY_POLICY, COOKIE, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde_json::json;

use crate::audit::Audit;
use crate::session::{Limiter, Sessions, Tickets, Who};
use crate::settings::Store;
use crate::users::{Role, Users};

/// The session cookie's name.
pub const COOKIE_NAME: &str = "pd_session";

/// Everything the handlers share.
pub struct AppState {
    pub users: Mutex<Users>,
    pub sessions: Mutex<Sessions>,
    pub tickets: Mutex<Tickets>,
    pub limiter: Mutex<Limiter>,
    pub settings: Store,
    pub audit: Audit,
    pub log_dir: PathBuf,
    pub static_dir: Option<PathBuf>,
    /// Seconds since the epoch; a test replaces it.
    pub clock: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Add `Secure` to the cookie (the console sits behind TLS).
    pub secure: bool,
    /// An operator or an administrator changes nothing until a second factor is on.
    pub require_mfa: bool,
}

pub type Shared = Arc<AppState>;

/// An answer that is an error: a status, a code that names the place it came from (`PD_<PART>_<REASON>`, listed in `webapp/docs/design.ja.md`) and a sentence.
pub struct Fail(pub StatusCode, pub &'static str, pub String);

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.2, "code": self.1}))).into_response()
    }
}

/// What a handler returns.
pub type Reply = Result<Response, Fail>;

/// The client's address as the server saw it.
#[derive(Clone)]
pub struct Source(pub String);

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl AppState {
    pub fn now(&self) -> u64 {
        (self.clock)()
    }
}

/// The session id in the `Cookie` headers, if there is one.
pub fn cookie_id(headers: &HeaderMap) -> Option<String> {
    let prefix = format!("{COOKIE_NAME}=");
    for value in headers.get_all(COOKIE) {
        for part in value.as_bytes().split(|b| *b == b';') {
            let part = part.trim_ascii();
            if let Some(rest) = part.strip_prefix(prefix.as_bytes()) {
                return String::from_utf8(rest.to_vec()).ok();
            }
        }
    }
    None
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn fail(status: StatusCode, code: &'static str, text: &str) -> Fail {
    Fail(status, code, text.to_owned())
}

/// The signed-in user, or 401.
pub fn who(state: &AppState, headers: &HeaderMap) -> Result<Who, Fail> {
    let id = cookie_id(headers).ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "PD_AUTH_NO_COOKIE", "sign in first"))?;
    let found = lock(&state.sessions).touch(&id, state.now());
    found.ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "PD_AUTH_SESSION_ENDED", "sign in first"))
}

/// A read: a session and at least `min`.
pub fn reader(state: &AppState, headers: &HeaderMap, min: Role) -> Result<Who, Fail> {
    let me = who(state, headers)?;
    if me.role < min {
        return Err(fail(StatusCode::FORBIDDEN, "PD_AUTH_ROLE", "your role cannot do that"));
    }
    Ok(me)
}

/// A change that sets up the second factor itself: a session, at least `min`, and the CSRF token of that session.
pub fn enroller(state: &AppState, headers: &HeaderMap, min: Role) -> Result<Who, Fail> {
    let me = reader(state, headers, min)?;
    let sent = headers.get("x-csrf-token").and_then(|v| std::str::from_utf8(v.as_bytes()).ok());
    if !sent.is_some_and(|token| same(token, &me.csrf)) {
        return Err(fail(StatusCode::FORBIDDEN, "PD_AUTH_CSRF", "the CSRF token is missing or wrong"));
    }
    Ok(me)
}

/// A change: as `enroller`, and an operator or an administrator must have a second factor on.
pub fn writer(state: &AppState, headers: &HeaderMap, min: Role) -> Result<Who, Fail> {
    let me = enroller(state, headers, min)?;
    if state.require_mfa && me.role >= Role::Operator && !lock(&state.users).mfa_on(&me.name) {
        return Err(fail(StatusCode::FORBIDDEN, "PD_AUTH_MFA_REQUIRED", "turn on a second factor first"));
    }
    Ok(me)
}

async fn note_source(mut req: Request, next: Next) -> Response {
    // DEFAULT: without a peer address (a test, a unix socket) every request shares one bucket named "unknown", which the limiter then counts as one source.
    let mut source = String::from("unknown");
    if let Some(peer) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        source = peer.0.ip().to_string();
    }
    req.extensions_mut().insert(Source(source));
    next.run(req).await
}

async fn harden(req: Request, next: Next) -> Response {
    let api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"));
    if api {
        h.insert("cache-control", HeaderValue::from_static("no-store"));
    }
    res
}

/// The router with every route and the two layers.
pub fn router(state: Shared) -> Router {
    use crate::{account, pages, setting};
    Router::new()
        .route("/healthz", get(pages::health))
        .route("/api/bootstrap", get(account::bootstrap))
        .route("/api/register", post(account::register))
        .route("/api/login", post(account::login))
        .route("/api/login/second", post(account::login_second))
        .route("/api/logout", post(account::logout))
        .route("/api/mfa/totp/begin", post(account::totp_begin))
        .route("/api/mfa/totp/confirm", post(account::totp_confirm))
        .route("/api/users", get(account::list).post(account::create))
        .route("/api/users/{name}", patch(account::change).delete(account::remove))
        .route("/api/settings", get(setting::catalog))
        .route("/api/settings/{id}", get(setting::read).put(setting::save))
        .route("/api/status", get(pages::status))
        .fallback(get(pages::file))
        .layer(middleware::from_fn(harden))
        .layer(middleware::from_fn(note_source))
        .with_state(state)
}

/// What the command line says.
pub struct Config {
    pub listen: SocketAddr,
    pub data: PathBuf,
    pub config: PathBuf,
    pub logs: PathBuf,
    pub static_dir: Option<PathBuf>,
    pub secure: bool,
    /// `--second-factor-optional`: operators and administrators may change settings without a second factor.
    pub mfa_optional: bool,
}

fn need(found: Option<PathBuf>, flag: &str) -> Result<PathBuf, String> {
    found.ok_or_else(|| format!("{flag} is required"))
}

/// Read the arguments. A console that listens beyond this machine must say so with `--allow-remote`.
pub fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut listen = SocketAddr::from(([127, 0, 0, 1], 8088));
    let (mut data, mut config, mut logs, mut static_dir) = (None, None, None, None);
    let (mut secure, mut remote, mut mfa_optional) = (false, false, false);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--secure" => secure = true,
            "--second-factor-optional" => mfa_optional = true,
            "--allow-remote" => remote = true,
            "--listen" | "--data" | "--config" | "--logs" | "--static" => {
                let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
                match flag.as_str() {
                    "--listen" => listen = value.parse().map_err(|e| format!("--listen: {e}"))?,
                    "--data" => data = Some(PathBuf::from(value)),
                    "--config" => config = Some(PathBuf::from(value)),
                    "--logs" => logs = Some(PathBuf::from(value)),
                    _ => static_dir = Some(PathBuf::from(value)),
                }
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    if !listen.ip().is_loopback() && !remote {
        return Err(String::from("--listen beyond this machine needs --allow-remote"));
    }
    Ok(Config { listen, data: need(data, "--data")?, config: need(config, "--config")?, logs: need(logs, "--logs")?, static_dir, secure, mfa_optional })
}

fn wall_clock() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => since.as_secs(),
        // DEFAULT: a clock set before 1970 reads as time 0, which ends every session at once.
        Err(_) => 0,
    }
}

/// Open the files and make the shared state.
pub fn build(c: &Config) -> Result<Shared, String> {
    std::fs::create_dir_all(&c.data).map_err(|e| format!("{}: {e}", c.data.display()))?;
    let users = Users::open(&c.data.join("users.json")).map_err(|e| e.to_string())?;
    let settings = Store::open(&c.config).map_err(|e| e.to_string())?;
    let audit = Audit::open(&c.data)?;
    Ok(Arc::new(AppState {
        users: Mutex::new(users),
        sessions: Mutex::new(Sessions::default()),
        tickets: Mutex::new(Tickets::default()),
        limiter: Mutex::new(Limiter::default()),
        settings,
        audit,
        log_dir: c.logs.clone(),
        static_dir: c.static_dir.clone(),
        clock: Box::new(wall_clock),
        secure: c.secure,
        require_mfa: !c.mfa_optional,
    }))
}

