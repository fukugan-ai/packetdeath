//! Sign-in, sign-out, the first administrator and the user list. `webapp/docs/design.ja.md`.
//!
//! A failed sign-in answers the same way whether the account exists or not,
//! and the answer to a wait is a 429 that does not say which of the two
//! counters (the account or the source) ran out.

use axum::extract::{Extension, Path, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::app::{cookie_id, lock, reader, who, writer, Fail, Reply, Shared, Source, COOKIE_NAME};
use crate::session::LIFETIME;
use crate::users::{Role, UserError};

#[derive(Deserialize)]
pub struct Credentials {
    pub name: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct NewUser {
    pub name: String,
    pub password: String,
    pub role: Role,
}

#[derive(Deserialize)]
pub struct Change {
    pub role: Option<Role>,
    pub disabled: Option<bool>,
    pub password: Option<String>,
}

fn fail(status: StatusCode, code: &'static str, text: &str) -> Fail {
    Fail(status, code, text.to_owned())
}

fn user_fail(error: UserError) -> Fail {
    let (status, code) = match error {
        UserError::BadName => (StatusCode::UNPROCESSABLE_ENTITY, "PD_USER_NAME"),
        UserError::WeakPassword => (StatusCode::UNPROCESSABLE_ENTITY, "PD_USER_PASSWORD"),
        UserError::Exists => (StatusCode::CONFLICT, "PD_USER_EXISTS"),
        UserError::LastAdmin => (StatusCode::CONFLICT, "PD_USER_LAST_ADMIN"),
        UserError::NotFound => (StatusCode::NOT_FOUND, "PD_USER_NOT_FOUND"),
        UserError::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "PD_USER_STORE"),
    };
    Fail(status, code, error.to_string())
}

/// Write one audit line. A failure to write is reported on stderr and does not undo the change that was made.
fn note(state: &Shared, user: &str, action: &'static str, target: &str, ok: bool) {
    if let Err(why) = state.audit.record(user, action, target, ok, (None, None)) {
        eprintln!("webapp: the audit line was not written: {why}");
    }
}

fn cookie_value(state: &Shared, id: &str, max_age: u64) -> Result<HeaderValue, Fail> {
    let secure = if state.secure { "; Secure" } else { "" };
    let text = format!("{COOKIE_NAME}={id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure}");
    HeaderValue::from_str(&text).map_err(|_| fail(StatusCode::INTERNAL_SERVER_ERROR, "PD_AUTH_COOKIE", "the cookie could not be built"))
}

fn signed_in(state: &Shared, name: &str, role: Role) -> Reply {
    let started = lock(&state.sessions).start(name, role, state.now());
    let (id, csrf) = started.map_err(|why| Fail(StatusCode::INTERNAL_SERVER_ERROR, "PD_AUTH_SESSION_START", why))?;
    let cookie = cookie_value(state, &id, LIFETIME)?;
    let body = Json(json!({"name": name, "role": role, "csrf": csrf}));
    let mut res = body.into_response();
    res.headers_mut().insert(SET_COOKIE, cookie);
    Ok(res)
}

/// Whether the console still waits for its first administrator, and who is signed in.
pub async fn bootstrap(State(state): State<Shared>, headers: HeaderMap) -> Reply {
    let empty = lock(&state.users).is_empty();
    let mut me = json!(null);
    if let Ok(found) = who(&state, &headers) {
        me = json!({"name": found.name, "role": found.role, "csrf": found.csrf});
    }
    Ok(Json(json!({"needs_register": empty, "me": me})).into_response())
}

/// The first administrator. Refused as soon as any user exists.
pub async fn register(State(state): State<Shared>, Json(body): Json<Credentials>) -> Reply {
    let now = state.now();
    {
        let mut users = lock(&state.users);
        if !users.is_empty() {
            return Err(fail(StatusCode::CONFLICT, "PD_USER_REGISTER_CLOSED", "the console already has users"));
        }
        users.create(&body.name, &body.password, Role::Admin, now).map_err(user_fail)?;
    }
    note(&state, &body.name, "register", &body.name, true);
    signed_in(&state, &body.name, Role::Admin)
}

fn too_many() -> Fail {
    fail(StatusCode::TOO_MANY_REQUESTS, "PD_AUTH_LIMITED", "too many failed sign-ins; try again later")
}

pub async fn login(State(state): State<Shared>, Extension(source): Extension<Source>, Json(body): Json<Credentials>) -> Reply {
    let now = state.now();
    if lock(&state.limiter).must_wait(&body.name, &source.0, now) {
        return Err(too_many());
    }
    let verified = lock(&state.users).verify(&body.name, &body.password);
    let Some(role) = verified else {
        lock(&state.limiter).failed(&body.name, &source.0, now);
        note(&state, &body.name, "login", &body.name, false);
        return Err(fail(StatusCode::UNAUTHORIZED, "PD_AUTH_LOGIN", "the account or the password is wrong"));
    };
    lock(&state.limiter).succeeded(&body.name);
    note(&state, &body.name, "login", &body.name, true);
    signed_in(&state, &body.name, role)
}

pub async fn logout(State(state): State<Shared>, headers: HeaderMap) -> Reply {
    let me = writer(&state, &headers, Role::Viewer)?;
    if let Some(id) = cookie_id(&headers) {
        lock(&state.sessions).end(&id);
    }
    note(&state, &me.name, "logout", &me.name, true);
    let mut res = Json(json!({"ok": true})).into_response();
    res.headers_mut().insert(SET_COOKIE, cookie_value(&state, "", 0)?);
    Ok(res)
}

pub async fn list(State(state): State<Shared>, headers: HeaderMap) -> Reply {
    reader(&state, &headers, Role::Admin)?;
    let users = lock(&state.users).list();
    Ok(Json(json!({"users": users})).into_response())
}

pub async fn create(State(state): State<Shared>, headers: HeaderMap, Json(body): Json<NewUser>) -> Reply {
    let me = writer(&state, &headers, Role::Admin)?;
    let made = lock(&state.users).create(&body.name, &body.password, body.role, state.now());
    note(&state, &me.name, "user-create", &body.name, made.is_ok());
    made.map_err(user_fail)?;
    Ok((StatusCode::CREATED, Json(json!({"ok": true}))).into_response())
}

fn apply(state: &Shared, name: &str, body: &Change) -> Result<(), UserError> {
    let mut users = lock(&state.users);
    if let Some(role) = body.role {
        users.set_role(name, role)?;
        lock(&state.sessions).set_role_of(name, role);
    }
    if let Some(disabled) = body.disabled {
        users.set_disabled(name, disabled)?;
        if disabled {
            lock(&state.sessions).end_all_of(name);
        }
    }
    if let Some(password) = &body.password {
        users.set_password(name, password)?;
        lock(&state.sessions).end_all_of(name);
    }
    Ok(())
}

pub async fn change(State(state): State<Shared>, headers: HeaderMap, Path(name): Path<String>, Json(body): Json<Change>) -> Reply {
    let me = writer(&state, &headers, Role::Admin)?;
    let done = apply(&state, &name, &body);
    note(&state, &me.name, "user-change", &name, done.is_ok());
    done.map_err(user_fail)?;
    Ok(Json(json!({"ok": true})).into_response())
}

pub async fn remove(State(state): State<Shared>, headers: HeaderMap, Path(name): Path<String>) -> Reply {
    let me = writer(&state, &headers, Role::Admin)?;
    let done = lock(&state.users).remove(&name);
    if done.is_ok() {
        lock(&state.sessions).end_all_of(&name);
    }
    note(&state, &me.name, "user-remove", &name, done.is_ok());
    done.map_err(user_fail)?;
    Ok(Json(json!({"ok": true})).into_response())
}
