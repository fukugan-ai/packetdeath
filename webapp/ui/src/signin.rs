//! Sign-in and the first administrator's registration. `webapp/docs/design.ja.md`.
//!
//! One frame, two fields (account, password), a switch that shows the
//! password, the language and the theme. The same frame serves both: the
//! first-run form differs in where it posts and in the password's hint.

use dioxus::prelude::*;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::i18n::{error_line, error_word, t};
use crate::mark::{LockIcon, Mark, PersonIcon};
use crate::theme;
use crate::{me_of, Me};

#[component]
pub fn Signin(first_run: bool, lang: Signal<String>, dark: Signal<bool>, me: Signal<Option<Me>>) -> Element {
    let mut name = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut reveal = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let l = lang();
    let title = t(&l, if first_run { "register" } else { "sign_in" });
    let password_label = t(&l, if first_run { "password_new" } else { "password" });
    let reveal_label = t(&l, if reveal() { "hide" } else { "show" });

    let submit = move |event: FormEvent| {
        event.prevent_default();
        if busy() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            let path = if first_run { "/api/register" } else { "/api/login" };
            let payload = json!({"name": name(), "password": password()});
            match api::send("POST", path, "", &payload).await {
                Ok(body) => match me_of(&body) {
                    Some(found) => {
                        password.set(String::new());
                        me.set(Some(found));
                    }
                    None => error.set(error_word(&lang(), 0)),
                },
                Err(failed) => error.set(error_line(&lang(), &failed)),
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
                    }
                    button { class: "primary", r#type: "submit", disabled: busy(), "{title}" }
                }
            }
        }
    }
}
