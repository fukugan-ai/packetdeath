//! The band at the top and the screen under it. `webapp/docs/design.ja.md`.

use dioxus::prelude::*;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

use crate::editor::Editor;
use crate::i18n::{t, word};
use crate::mark::Mark;
use crate::security::Security;
use crate::status::Status;
use crate::theme;
use crate::users::Users;
use crate::{api, Me};

/// The switch that shows the state itself: on is dark.
#[component]
pub fn ThemeSwitch(lang: Signal<String>, dark: Signal<bool>) -> Element {
    let l = lang();
    rsx! {
        span { class: "switch",
            span { id: "theme-label", "{t(&l, \"dark\")}" }
            button {
                id: "themeToggle",
                class: "switch-track",
                r#type: "button",
                role: "switch",
                aria_checked: "{dark()}",
                aria_labelledby: "theme-label",
                onclick: move |_| {
                    let next = !dark();
                    dark.set(next);
                    theme::set_theme(if next { "dark" } else { "light" });
                },
                span { class: "switch-thumb" }
            }
        }
    }
}

const TABS: [&str; 7] = ["status", "ips", "ids", "waf", "av", "users", "security"];

/// Whether a signed-in user is told that changes wait for a second factor.
fn needs_second_factor(role: &str, mfa: bool) -> bool {
    !mfa && role != "viewer"
}

fn tab_visible(tab: &str, role: &str) -> bool {
    tab != "users" || role == "admin"
}

#[component]
pub fn Shell(user: Me, lang: Signal<String>, dark: Signal<bool>, me: Signal<Option<Me>>) -> Element {
    let mut tab = use_signal(|| "status");
    let l = lang();
    let csrf = user.csrf.clone();
    let sign_out = move |_| {
        let csrf = csrf.clone();
        spawn_local(async move {
            // The session ends on the server first; the screen goes back to sign-in either way.
            if api::send("POST", "/api/logout", &csrf, &json!({})).await.is_err() {
                web_sys::console::warn_1(&"sign-out did not reach the server".into());
            }
            me.set(None);
        });
    };
    let role_word = word(&l, "role", &user.role);
    rsx! {
        div { class: "shell",
            header { class: "band",
                span { class: "band-brand", Mark { size: 36 } span { "{t(&l, \"app\")}" } }
                nav { class: "tabs", aria_label: "Screens",
                    for name in TABS.iter().filter(|name| tab_visible(name, &user.role)) {
                        button {
                            key: "{name}",
                            class: if tab() == *name { "tab tab-on" } else { "tab" },
                            r#type: "button",
                            aria_current: if tab() == *name { "page" } else { "false" },
                            onclick: { let name = *name; move |_| tab.set(name) },
                            "{word(&l, \"tab\", name)}"
                        }
                    }
                }
                span { class: "band-end",
                    select {
                        id: "languageSelect",
                        aria_label: "{t(&l, \"language\")}",
                        value: "{l}",
                        onchange: move |event| {
                            let next = event.value();
                            theme::set_lang(&next);
                            lang.set(next);
                        },
                        option { value: "ja", "日本語" }
                        option { value: "en", "English" }
                    }
                    ThemeSwitch { lang, dark }
                    span { class: "who", "{user.name} ({role_word})" }
                    button { class: "quiet", r#type: "button", onclick: sign_out, "{t(&l, \"sign_out\")}" }
                }
            }
            if needs_second_factor(&user.role, user.mfa) {
                p { class: "notice notice-danger", id: "mfa-banner", role: "status", "{t(&l, \"mfa_banner\")}" }
            }
            main { class: "screen",
                match tab() {
                    "status" => rsx! { Status { lang, me } },
                    "users" => rsx! { Users { lang, user: user.clone(), me } },
                    "security" => rsx! { Security { lang, user: user.clone(), me } },
                    part => rsx! { Editor { key: "{part}", part: part.to_owned(), lang, user: user.clone(), me } },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_administrator_sees_the_users_tab() {
        assert!(tab_visible("users", "admin"));
        assert!(!tab_visible("users", "operator"));
        assert!(!tab_visible("users", "viewer"));
        assert!(TABS.iter().filter(|name| tab_visible(name, "viewer")).count() == 6);
    }

    #[test]
    fn only_a_role_that_changes_things_is_told_to_turn_on_the_factor() {
        assert!(needs_second_factor("admin", false));
        assert!(needs_second_factor("operator", false));
        assert!(!needs_second_factor("viewer", false));
        assert!(!needs_second_factor("admin", true));
    }
}
