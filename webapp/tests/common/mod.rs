//! A console in a fresh folder, a clock the test moves, and a one-call request helper.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use packetdeath_webapp::app::{router, AppState, Shared};
use packetdeath_webapp::audit::Audit;
use packetdeath_webapp::session::{Limiter, Sessions, Tickets};
use packetdeath_webapp::settings::Store;
use packetdeath_webapp::users::Users;
use serde_json::Value;
use tower::ServiceExt;

pub type Fault = Box<dyn std::error::Error>;

pub const PASSWORD: &str = "correct horse battery";

pub struct Rig {
    pub app: Router,
    pub state: Shared,
    pub now: Arc<AtomicU64>,
    pub dir: PathBuf,
}

/// An answer. The text is kept as it came; `body` reads it as JSON where the test expects JSON.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub text: String,
}

impl Reply {
    pub fn body(&self) -> Result<Value, Fault> {
        Ok(serde_json::from_str::<Value>(&self.text)?)
    }
}

/// A signed-in user: the cookie header value and the CSRF token.
pub struct Login {
    pub cookie: String,
    pub csrf: String,
}

/// A console that does not insist on a second factor for operators and administrators.
pub fn rig(name: &str) -> Result<Rig, Fault> {
    rig_with(name, false)
}

/// A console that insists on a second factor, as the command line does by default.
pub fn rig_requiring_mfa(name: &str) -> Result<Rig, Fault> {
    rig_with(name, true)
}

fn rig_with(name: &str, require_mfa: bool) -> Result<Rig, Fault> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("it").join(format!("{}-{name}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    for part in ["data", "config", "logs"] {
        std::fs::create_dir_all(dir.join(part))?;
    }
    let now = Arc::new(AtomicU64::new(1_800_000_000));
    let clock = Arc::clone(&now);
    let state: Shared = Arc::new(AppState {
        users: Mutex::new(Users::open(&dir.join("data").join("users.json"))?),
        sessions: Mutex::new(Sessions::default()),
        tickets: Mutex::new(Tickets::default()),
        limiter: Mutex::new(Limiter::default()),
        settings: Store::open(&dir.join("config"))?,
        audit: Audit::open(&dir.join("data"))?,
        log_dir: dir.join("logs"),
        static_dir: None,
        clock: Box::new(move || clock.load(Ordering::SeqCst)),
        secure: false,
        require_mfa,
    });
    Ok(Rig { app: router(Arc::clone(&state)), state, now, dir })
}

impl Rig {
    pub fn advance(&self, seconds: u64) {
        self.now.fetch_add(seconds, Ordering::SeqCst);
    }

    pub async fn call(&self, method: Method, uri: &str, who: Option<&Login>, csrf: bool, body: Option<Value>) -> Result<Reply, Fault> {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(login) = who {
            req = req.header("cookie", &login.cookie);
            if csrf {
                req = req.header("x-csrf-token", &login.csrf);
            }
        }
        let mut payload = Body::empty();
        if let Some(value) = body {
            req = req.header("content-type", "application/json");
            payload = Body::from(serde_json::to_vec(&value)?);
        }
        let res = self.app.clone().oneshot(req.body(payload)?).await?;
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await?.to_bytes();
        Ok(Reply { status: parts.status, headers: parts.headers, text: String::from_utf8_lossy(&bytes).into_owned() })
    }

    pub async fn register(&self, name: &str) -> Result<Login, Fault> {
        let body = serde_json::json!({"name": name, "password": PASSWORD});
        let reply = self.call(Method::POST, "/api/register", None, false, Some(body)).await?;
        login_of(&reply)
    }

    pub async fn sign_in(&self, name: &str, password: &str) -> Result<Reply, Fault> {
        let body = serde_json::json!({"name": name, "password": password});
        self.call(Method::POST, "/api/login", None, false, Some(body)).await
    }

    /// An administrator makes `name` with `role`, and `name` signs in.
    pub async fn user_with(&self, admin: &Login, name: &str, role: &str) -> Result<Login, Fault> {
        let body = serde_json::json!({"name": name, "password": PASSWORD, "role": role});
        let made = self.call(Method::POST, "/api/users", Some(admin), true, Some(body)).await?;
        assert_eq!(made.status, StatusCode::CREATED);
        login_of(&self.sign_in(name, PASSWORD).await?)
    }
}

pub fn login_of(reply: &Reply) -> Result<Login, Fault> {
    let Some(set) = reply.headers.get("set-cookie") else {
        return Err("no Set-Cookie in the answer".into());
    };
    let text = String::from_utf8_lossy(set.as_bytes()).into_owned();
    let Some(pair) = text.split(';').next() else {
        return Err("empty Set-Cookie".into());
    };
    let body = reply.body()?;
    let Some(csrf) = body.get("csrf").and_then(Value::as_str) else {
        return Err("no csrf in the answer".into());
    };
    Ok(Login { cookie: pair.to_owned(), csrf: csrf.to_owned() })
}
