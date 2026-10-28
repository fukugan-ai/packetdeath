//! Passkey routes: add a key, and sign in with one as the second step. `webapp/docs/design.ja.md` stage 14.
//!
//! A key is bound to the name given by `--rp-id` and `--origin`. Without them
//! these routes answer 404 and nothing else about sign-in changes.

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::account::{fail, note, signed_in, too_many};
use crate::app::{enroller, lock, Fail, Reply, Shared, Source};
use crate::users::Role;
use crate::webauthn::{self, Relying};

#[derive(Deserialize)]
pub struct Created {
    #[serde(rename = "clientDataJSON")]
    client_data: String,
    #[serde(rename = "attestationObject")]
    attestation: String,
}

#[derive(Deserialize)]
pub struct Ticket {
    ticket: String,
}

#[derive(Deserialize)]
pub struct Signed {
    ticket: String,
    id: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data: String,
    signature: String,
}

fn relying(state: &Shared) -> Result<&Relying, Fail> {
    state.relying.as_ref().ok_or_else(|| fail(StatusCode::NOT_FOUND, "PD_MFA_PASSKEY_OFF", "passkeys are off: start the console with --rp-id and --origin"))
}

fn bad_answer(error: webauthn::WebauthnError) -> Fail {
    fail(StatusCode::UNPROCESSABLE_ENTITY, "PD_MFA_PASSKEY", &error.to_string())
}

fn challenge_gone() -> Fail {
    fail(StatusCode::UNPROCESSABLE_ENTITY, "PD_MFA_PASSKEY_CHALLENGE", "the challenge expired or was used; start again")
}

fn store_fail(why: String) -> Fail {
    fail(StatusCode::INTERNAL_SERVER_ERROR, "PD_MFA_STORE", &why)
}

/// The options a browser passes to `navigator.credentials.create`.
pub async fn register_begin(State(state): State<Shared>, headers: HeaderMap) -> Reply {
    let me = enroller(&state, &headers, Role::Viewer)?;
    let rp = relying(&state)?;
    let issued = lock(&state.challenges).issue(&format!("register:{}", me.name), state.now());
    let challenge = issued.map_err(store_fail)?;
    let ids = lock(&state.users).key_ids(&me.name);
    let handle = Sha256::digest(me.name.as_bytes());
    Ok(Json(webauthn::registration_options(rp, &handle, &me.name, &challenge, &ids)).into_response())
}

/// Keep the key a browser made. The first second factor of the user also brings the recovery codes.
pub async fn register_finish(State(state): State<Shared>, headers: HeaderMap, Json(body): Json<Created>) -> Reply {
    let me = enroller(&state, &headers, Role::Viewer)?;
    let rp = relying(&state)?;
    let taken = lock(&state.challenges).take(&format!("register:{}", me.name), state.now());
    let challenge = taken.ok_or_else(challenge_gone)?;
    let client = webauthn::unb64(&body.client_data).map_err(bad_answer)?;
    let object = webauthn::unb64(&body.attestation).map_err(bad_answer)?;
    let made = webauthn::finish_registration(rp, &challenge, &client, &object);
    note(&state, &me.name, "passkey-add", &me.name, made.is_ok());
    let made = made.map_err(bad_answer)?;
    let kept = lock(&state.users).add_key(&me.name, &made.credential_id, &made.public_key, made.sign_count);
    let recovery = kept.map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "PD_USER_STORE", &e.to_string()))?;
    Ok(Json(json!({"ok": true, "recovery": recovery})).into_response())
}

/// The options a browser passes to `navigator.credentials.get` for a sign-in waiting on its second step.
pub async fn login_begin(State(state): State<Shared>, Json(body): Json<Ticket>) -> Reply {
    let now = state.now();
    let owner = lock(&state.tickets).owner(&body.ticket, now);
    let Some((name, _)) = owner else {
        return Err(fail(StatusCode::UNAUTHORIZED, "PD_AUTH_TICKET", "the sign-in took too long or was used up; enter the password again"));
    };
    let rp = relying(&state)?;
    let ids = lock(&state.users).key_ids(&name);
    if ids.is_empty() {
        return Err(fail(StatusCode::CONFLICT, "PD_MFA_PASSKEY_NONE", "this account has no passkey"));
    }
    let issued = lock(&state.challenges).issue(&format!("login:{}", body.ticket), now);
    let challenge = issued.map_err(store_fail)?;
    Ok(Json(webauthn::assertion_options(rp, &challenge, &ids)).into_response())
}

fn missed(state: &Shared, ticket: &str, name: &str, source: &str, now: u64) -> Fail {
    lock(&state.tickets).missed(ticket);
    lock(&state.limiter).failed(name, source, now);
    note(state, name, "login-passkey", name, false);
    fail(StatusCode::UNAUTHORIZED, "PD_AUTH_SECOND", "the passkey was not accepted")
}

/// Finish a sign-in with a passkey.
pub async fn login_finish(State(state): State<Shared>, Extension(source): Extension<Source>, Json(body): Json<Signed>) -> Reply {
    let now = state.now();
    let owner = lock(&state.tickets).owner(&body.ticket, now);
    let Some((name, role)) = owner else {
        return Err(fail(StatusCode::UNAUTHORIZED, "PD_AUTH_TICKET", "the sign-in took too long or was used up; enter the password again"));
    };
    if lock(&state.limiter).must_wait(&name, &source.0, now) {
        return Err(too_many());
    }
    let rp = relying(&state)?;
    let taken = lock(&state.challenges).take(&format!("login:{}", body.ticket), now);
    let challenge = taken.ok_or_else(challenge_gone)?;
    let (Ok(id), Ok(data), Ok(client), Ok(signature)) = (
        webauthn::unb64(&body.id),
        webauthn::unb64(&body.authenticator_data),
        webauthn::unb64(&body.client_data),
        webauthn::unb64(&body.signature),
    ) else {
        return Err(missed(&state, &body.ticket, &name, &source.0, now));
    };
    let kept = lock(&state.users).key_for(&name, &id);
    let Some((public_key, count)) = kept else {
        return Err(missed(&state, &body.ticket, &name, &source.0, now));
    };
    let Ok(new_count) = webauthn::finish_assertion(rp, &challenge, &public_key, count, &data, &client, &signature) else {
        return Err(missed(&state, &body.ticket, &name, &source.0, now));
    };
    let stored = lock(&state.users).set_key_count(&name, &id, new_count);
    stored.map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, "PD_USER_STORE", &e.to_string()))?;
    lock(&state.tickets).spend(&body.ticket);
    lock(&state.limiter).succeeded(&name);
    note(&state, &name, "login", &name, true);
    signed_in(&state, &name, role)
}
