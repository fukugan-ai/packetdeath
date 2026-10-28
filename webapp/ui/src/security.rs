//! The security screen: turn on a second factor and keep the recovery codes. `webapp/docs/design.ja.md`.
//!
//! Three states in one frame: nothing begun, a secret waiting for its first code,
//! and the recovery codes shown once.

use dioxus::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::i18n::{error_line, error_word, t};
use crate::{api, passkey, Me};

#[derive(Clone, Debug, PartialEq)]
enum Stage {
    Idle,
    Pending { secret: String, uri: String },
    Codes(Vec<String>),
}

fn pending_of(body: &Value) -> Option<Stage> {
    Some(Stage::Pending { secret: body.get("secret")?.as_str()?.to_owned(), uri: body.get("uri")?.as_str()?.to_owned() })
}

fn codes_of(body: &Value) -> Option<Stage> {
    let rows = body.get("recovery")?.as_array()?;
    Some(Stage::Codes(rows.iter().filter_map(|row| row.as_str().map(str::to_owned)).collect()))
}

/// What adding a passkey came to.
enum PasskeyAdded {
    /// It was the first second factor: the recovery codes are shown once.
    WithCodes(Stage),
    Only,
}

/// Why adding a passkey failed: the server refused, or the browser did.
enum PasskeyFailed {
    Server(api::ApiError),
    Browser(String),
}

impl PasskeyFailed {
    fn into_line(self, lang: &str) -> String {
        match self {
            PasskeyFailed::Server(failed) => error_line(lang, &failed),
            PasskeyFailed::Browser(why) => passkey::browser_line(lang, &why),
        }
    }
}

async fn enroll_passkey(csrf: &str) -> Result<PasskeyAdded, PasskeyFailed> {
    let options = api::send("POST", "/api/mfa/webauthn/begin", csrf, &json!({})).await.map_err(PasskeyFailed::Server)?;
    let made = passkey::create(&options).await.map_err(PasskeyFailed::Browser)?;
    let done = api::send("POST", "/api/mfa/webauthn/finish", csrf, &made).await.map_err(PasskeyFailed::Server)?;
    match codes_of(&done) {
        Some(next) => Ok(PasskeyAdded::WithCodes(next)),
        None => Ok(PasskeyAdded::Only),
    }
}

#[component]
pub fn Security(lang: Signal<String>, user: Me, me: Signal<Option<Me>>) -> Element {
    let mut stage = use_signal(|| Stage::Idle);
    let mut code = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut notice = use_signal(String::new);
    let l = lang();

    let csrf = user.csrf.clone();
    let begin = move |_| {
        if busy() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let csrf = csrf.clone();
        spawn_local(async move {
            match api::send("POST", "/api/mfa/totp/begin", &csrf, &json!({})).await {
                Ok(body) => match pending_of(&body) {
                    Some(next) => stage.set(next),
                    None => error.set(error_word(&lang(), 0)),
                },
                Err(failed) => error.set(error_line(&lang(), &failed)),
            }
            busy.set(false);
        });
    };

    let csrf = user.csrf.clone();
    let confirm = move |event: FormEvent| {
        event.prevent_default();
        if busy() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let csrf = csrf.clone();
        spawn_local(async move {
            match api::send("POST", "/api/mfa/totp/confirm", &csrf, &json!({"code": code()})).await {
                Ok(body) => match codes_of(&body) {
                    Some(next) => {
                        code.set(String::new());
                        stage.set(next);
                    }
                    None => error.set(error_word(&lang(), 0)),
                },
                Err(failed) => error.set(error_line(&lang(), &failed)),
            }
            busy.set(false);
        });
    };

    let csrf = user.csrf.clone();
    let add_passkey = move |_| {
        if busy() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        let csrf = csrf.clone();
        spawn_local(async move {
            match enroll_passkey(&csrf).await {
                Ok(PasskeyAdded::WithCodes(next)) => stage.set(next),
                Ok(PasskeyAdded::Only) => {
                    notice.set(t(&lang(), "mfa_passkey_added"));
                    let next = me.read().clone().map(|m| Me { mfa: true, ..m });
                    me.set(next);
                }
                Err(failed) => error.set(failed.into_line(&lang())),
            }
            busy.set(false);
        });
    };

    let saved = {
        let user = user.clone();
        move |_| {
            stage.set(Stage::Idle);
            me.set(Some(Me { mfa: true, ..user.clone() }));
        }
    };

    rsx! {
        section { class: "security",
            h2 { "{t(&l, \"security\")}" }
            p { class: "notice notice-danger", role: "alert", hidden: error.read().is_empty(), "{error}" }
            p { class: "notice", id: "mfa-notice", role: "status", hidden: notice.read().is_empty(), "{notice}" }
            match stage() {
                Stage::Idle => rsx! {
                    if user.mfa {
                        p { id: "mfa-state", "{t(&l, \"mfa_on\")}" }
                    } else {
                        p { id: "mfa-state", "{t(&l, \"mfa_off\")}" }
                        button { class: "primary", id: "mfa-begin", r#type: "button", disabled: busy(), onclick: begin, "{t(&l, \"mfa_begin\")}" }
                    }
                    p { button { class: "quiet", id: "mfa-passkey", r#type: "button", disabled: busy(), onclick: add_passkey, "{t(&l, \"mfa_passkey_add\")}" } }
                    p { class: "hint", "{t(&l, \"mfa_passkey_note\")}" }
                },
                Stage::Pending { secret, uri } => rsx! {
                    p { "{t(&l, \"mfa_secret\")}" }
                    p { code { id: "mfa-secret", "{secret}" } }
                    p { a { id: "mfa-uri", href: "{uri}", "{t(&l, \"mfa_open_app\")}" } }
                    form { id: "mfa-form", onsubmit: confirm, novalidate: true,
                        label { r#for: "mfa-code", "{t(&l, \"mfa_code\")}" }
                        input {
                            id: "mfa-code", name: "one-time-code", r#type: "text",
                            inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, required: true,
                            value: "{code}", oninput: move |event| code.set(event.value()),
                        }
                        button { class: "primary", r#type: "submit", disabled: busy(), "{t(&l, \"mfa_confirm\")}" }
                    }
                },
                Stage::Codes(list) => rsx! {
                    p { class: "notice", id: "mfa-codes-note", "{t(&l, \"mfa_codes\")}" }
                    ul { id: "mfa-codes",
                        for item in list.iter() {
                            li { key: "{item}", code { "{item}" } }
                        }
                    }
                    button { class: "primary", id: "mfa-saved", r#type: "button", onclick: saved, "{t(&l, \"mfa_saved\")}" }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_begin_answer_needs_the_secret_and_the_address() {
        assert_eq!(pending_of(&json!({"secret": "S", "uri": "otpauth://x"})), Some(Stage::Pending { secret: "S".into(), uri: "otpauth://x".into() }));
        assert_eq!(pending_of(&json!({"secret": "S"})), None);
    }

    #[test]
    fn a_confirm_answer_is_the_list_of_codes() {
        assert_eq!(codes_of(&json!({"recovery": ["A-B", "C-D"]})), Some(Stage::Codes(vec!["A-B".into(), "C-D".into()])));
        assert_eq!(codes_of(&json!({})), None);
    }
}
