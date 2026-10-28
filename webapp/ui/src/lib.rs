//! The screens of the packetdeath console. `webapp/docs/design.ja.md`.
//!
//! One Dioxus island. It asks the server who is signed in, then shows the
//! sign-in frame or the shell. Every rule is the server's; a screen only hides
//! what a role cannot do and shows the refusal it gets.

use std::rc::Rc;

use dioxus::prelude::*;
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::spawn_local;

pub mod api;
pub mod editor;
pub mod i18n;
pub mod mark;
pub mod passkey;
pub mod security;
pub mod shell;
pub mod signin;
pub mod status;
pub mod theme;
pub mod users;

use crate::i18n::{error_line, t};
use crate::shell::Shell;
use crate::signin::Signin;

/// The signed-in user as the server described them.
#[derive(Clone, Debug, PartialEq)]
pub struct Me {
    pub name: String,
    pub role: String,
    pub csrf: String,
    /// A second factor is on.
    pub mfa: bool,
}

/// The user in a sign-in or bootstrap answer; `null` or a body without the three fields is nobody.
pub fn me_of(body: &Value) -> Option<Me> {
    Some(Me {
        name: body.get("name")?.as_str()?.to_owned(),
        role: body.get("role")?.as_str()?.to_owned(),
        csrf: body.get("csrf")?.as_str()?.to_owned(),
        mfa: body.get("mfa").and_then(Value::as_bool) == Some(true),
    })
}

#[wasm_bindgen(start)]
pub fn launch() {
    // The island does not write the page's history.
    let config = dioxus_web::Config::new().rootname("app").history(Rc::new(dioxus::history::MemoryHistory::default()));
    dioxus_web::launch::launch_cfg(App, config);
}

#[component]
fn App() -> Element {
    let lang = use_signal(theme::lang);
    let dark = use_signal(|| theme::theme() == "dark");
    let mut me = use_signal(|| None::<Me>);
    let mut first_run = use_signal(|| None::<bool>);
    let mut error = use_signal(String::new);

    use_effect(move || {
        theme::apply_theme(if dark() { "dark" } else { "light" });
        theme::apply_lang(&lang());
    });
    // Once someone is signed in the console has users, so the sign-out that follows shows the sign-in form.
    use_effect(move || {
        if me.read().is_some() {
            first_run.set(Some(false));
        }
    });
    use_effect(move || {
        spawn_local(async move {
            match api::get("/api/bootstrap").await {
                Ok(body) => {
                    me.set(me_of(&body["me"]));
                    first_run.set(Some(body["needs_register"] == true));
                }
                Err(failed) => error.set(error_line(&lang(), &failed)),
            }
        });
    });

    let l = lang();
    let current = me.read().clone();
    match (current, first_run()) {
        (Some(user), _) => rsx! { Shell { user, lang, dark, me } },
        (None, Some(first)) => rsx! { Signin { first_run: first, lang, dark, me } },
        (None, None) => rsx! {
            main { class: "boot",
                p { class: "notice notice-danger", role: "alert", hidden: error.read().is_empty(), "{error}" }
                p { class: "absent", hidden: !error.read().is_empty(), "{t(&l, \"loading\")}" }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nobody_is_nobody() {
        assert_eq!(me_of(&json!(null)), None);
        assert_eq!(me_of(&json!({"name": "a", "role": "admin"})), None);
    }

    #[test]
    fn a_full_answer_is_a_user() {
        let found = me_of(&json!({"name": "a", "role": "admin", "csrf": "t"}));
        assert_eq!(found, Some(Me { name: "a".into(), role: "admin".into(), csrf: "t".into(), mfa: false }));
        let with = me_of(&json!({"name": "a", "role": "admin", "csrf": "t", "mfa": true}));
        assert_eq!(with.map(|m| m.mfa), Some(true));
    }
}
