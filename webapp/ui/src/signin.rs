//! Sign-in and the first administrator's registration. `webapp/docs/design.ja.md`.
//!
//! One frame, two fields (account, password), a switch that shows the
//! password, the language and the theme. The same frame serves both: the
//! first-run form differs in where it posts and in the password's hint.

use dioxus::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::i18n::{error_line, error_word, t};
use crate::mark::{LockIcon, Mark, PersonIcon};
use crate::theme;
use crate::{me_of, Me};

/// The ticket of a sign-in that waits for its second step; any other answer has none.
fn ticket_of(body: &Value) -> Option<String> {
    if body.get("mfa").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    body.get("ticket")?.as_str().map(str::to_owned)
}

#[component]
pub fn Signin(first_run: bool, lang: Signal<String>, dark: Signal<bool>, me: Signal<Option<Me>>) -> Element {
    let mut name = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut reveal = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut ticket = use_signal(|| None::<String>);
    let mut code = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let l = lang();
    let title = t(&l, if first_run { "register" } else { "sign_in" });
    let password_label = t(&l, if first_run { "password_new" } else { "password" });
    let reveal_label = t(&l, if reveal() { "hide" } else { "show" });

    let submit = move |event: FormEvent| {
        event.prevent_default();
        if busy() {
            return;
        }
        error.set(String::new());
        if first_run && password() != confirm() {
            error.set(t(&lang(), "err_mismatch"));
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let waiting = ticket();
            let path = match (&waiting, first_run) {
                (Some(_), _) => "/api/login/second",
                (None, true) => "/api/register",
                (None, false) => "/api/login",
            };
            let payload = match &waiting {
                Some(id) => json!({"ticket": id, "code": code()}),
                None => json!({"name": name(), "password": password()}),
            };
            match api::send("POST", path, "", &payload).await {
                Ok(body) => match (ticket_of(&body), me_of(&body)) {
                    (Some(id), _) => {
                        password.set(String::new());
                        ticket.set(Some(id));
                    }
                    (None, Some(found)) => {
                        password.set(String::new());
                        code.set(String::new());
                        ticket.set(None);
                        me.set(Some(found));
                    }
                    (None, None) => error.set(error_word(&lang(), 0)),
                },
                Err(failed) => {
                    if failed.code == "PD_AUTH_TICKET" {
                        ticket.set(None);
                    }
                    error.set(error_line(&lang(), &failed));
                }
            }
            busy.set(false);
        });
    };

    rsx! {
        div { class: "auth-root",
            div { class: "auth-figure", Mark { size: 160 } }
            nav { class: "auth-utilities", aria_label: "Display settings",
                label { class: "sr-only", r#for: "languageSelect", "{t(&l, \"language\")}" }
                select {
                    id: "languageSelect",
                    value: "{l}",
                    onchange: move |event| {
                        let next = event.value();
                        theme::set_lang(&next);
                        lang.set(next);
                    },
                    option { value: "ja", "日本語" }
                    option { value: "en", "English" }
                }
                crate::shell::ThemeSwitch { lang, dark }
            }
            main { class: "auth-stage", aria_busy: "{busy()}",
                h1 { class: "sr-only", "{title}" }
                form { id: "authForm", class: "auth-form", onsubmit: submit, novalidate: true,
                    p { class: "notice notice-danger", role: "alert", hidden: error.read().is_empty(), "{error}" }
                    if ticket().is_some() {
                        div { class: "auth-fields",
                            label { class: "auth-field",
                                span { "{t(&l, \"second_hint\")}" }
                                span { class: "auth-control",
                                    LockIcon {}
                                    input {
                                        r#type: "text", id: "second-code", name: "one-time-code",
                                        value: "{code}",
                                        oninput: move |event| code.set(event.value()),
                                        autocomplete: "one-time-code", inputmode: "numeric", maxlength: 32, required: true,
                                        placeholder: "{t(&l, \"second_title\")}",
                                    }
                                }
                            }
                        }
                        button { class: "primary", r#type: "submit", disabled: busy(), "{t(&l, \"second_submit\")}" }
                        button {
                            class: "quiet", r#type: "button", id: "second-back",
                            onclick: move |_| { ticket.set(None); code.set(String::new()); error.set(String::new()); },
                            "{t(&l, \"second_back\")}"
                        }
                    } else {
                    div { class: "auth-fields",
                        label { class: "auth-field",
                            span { class: "sr-only", "{t(&l, \"account\")}" }
                            span { class: "auth-control",
                                PersonIcon {}
                                input {
                                    r#type: "text", id: "username", name: "username",
                                    value: "{name}",
                                    oninput: move |event| name.set(event.value()),
                                    autocomplete: "username", maxlength: 128, required: true,
                                    placeholder: "{t(&l, \"account\")}",
                                }
                            }
                        }
                        label { class: "auth-field",
                            span { class: "sr-only", "{password_label}" }
                            span { class: "auth-control auth-control-password",
                                LockIcon {}
                                input {
                                    id: "password", name: if first_run { "new-password" } else { "password" },
                                    r#type: if reveal() { "text" } else { "password" },
                                    value: "{password}",
                                    oninput: move |event| password.set(event.value()),
                                    autocomplete: if first_run { "new-password" } else { "current-password" },
                                    minlength: if first_run { "12" } else { "1" }, required: true,
                                    placeholder: "{password_label}",
                                }
                                button {
                                    class: "password-visibility",
                                    r#type: "button",
                                    aria_pressed: "{reveal()}",
                                    aria_label: "{reveal_label}",
                                    title: "{reveal_label}",
                                    onclick: move |_| { let next = !reveal(); reveal.set(next); },
                                    span { class: "password-visibility-icon", "aria-hidden": "true" }
                                }
                            }
                        }
                        if first_run {
                            label { class: "auth-field",
                                span { class: "sr-only", "{t(&l, \"password_again\")}" }
                                span { class: "auth-control auth-control-password",
                                    LockIcon {}
                                    input {
                                        id: "password-confirm", name: "new-password-confirm",
                                        r#type: if reveal() { "text" } else { "password" },
                                        value: "{confirm}",
                                        oninput: move |event| confirm.set(event.value()),
                                        autocomplete: "new-password", minlength: "12", required: true,
                                        placeholder: "{t(&l, \"password_again\")}",
                                    }
                                }
                            }
                        }
                    }
                    button { class: "primary", r#type: "submit", disabled: busy(), "{title}" }
                    }
                }
            }
        }
    }
}
