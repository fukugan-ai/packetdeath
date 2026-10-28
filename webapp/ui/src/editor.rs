//! The settings of one part (ips, ids, waf, av). `webapp/docs/design.ja.md`.
//!
//! The server checks every save with the tool's own parser. A file with an
//! unreadable line is not written, and the screen lists each line with its reason.

use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api::{self, BadLine};
use crate::i18n::{error_word, t};
use crate::Me;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Kind {
    pub id: String,
    pub part: String,
    pub file: String,
    pub hot: bool,
}

/// The kinds that belong to `part`, in the server's order.
pub fn kinds_of(catalog: &Value, part: &str) -> Vec<Kind> {
    let Some(rows) = catalog.get("settings").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for row in rows {
        if let Ok(kind) = serde_json::from_value::<Kind>(row.clone()) {
            if kind.part == part {
                found.push(kind);
            }
        }
    }
    found
}

/// Whether the running tool rereads the file by itself decides the note under the name.
fn reload_key(hot: bool) -> &'static str {
    if hot {
        "reload_hot"
    } else {
        "reload_cold"
    }
}

#[component]
pub fn Editor(part: String, lang: Signal<String>, user: Me, me: Signal<Option<Me>>) -> Element {
    let mut kinds = use_signal(Vec::<Kind>::new);
    let mut selected = use_signal(String::new);
    let mut text = use_signal(String::new);
    let mut bad = use_signal(Vec::<BadLine>::new);
    let mut error = use_signal(String::new);
    let mut done = use_signal(String::new);
    let can_edit = user.role != "viewer";
    let csrf = user.csrf.clone();
    let wanted = part.clone();

    use_effect(move || {
        let wanted = wanted.clone();
        spawn_local(async move {
            match api::get("/api/settings").await {
                Ok(body) => {
                    let mine = kinds_of(&body, &wanted);
                    if let Some(first) = mine.first() {
                        selected.set(first.id.clone());
                    }
                    kinds.set(mine);
                }
                Err(failed) if failed.is_signed_out() => me.set(None),
                Err(failed) => error.set(error_word(&lang(), failed.status)),
            }
        });
    });

    use_effect(move || {
        let id = selected();
        if id.is_empty() {
            return;
        }
        bad.set(Vec::new());
        done.set(String::new());
        spawn_local(async move {
            match api::get(&format!("/api/settings/{id}")).await {
                Ok(body) => match body.get("text").and_then(Value::as_str) {
                    Some(found) => text.set(found.to_owned()),
                    None => error.set(error_word(&lang(), 0)),
                },
                Err(failed) if failed.is_signed_out() => me.set(None),
                Err(failed) => error.set(error_word(&lang(), failed.status)),
            }
        });
    });

    let save = move |_| {
        let id = selected();
        let csrf = csrf.clone();
        error.set(String::new());
        done.set(String::new());
        bad.set(Vec::new());
        spawn_local(async move {
            let body = json!({"text": text()});
            match api::send("PUT", &format!("/api/settings/{id}"), &csrf, &body).await {
                Ok(_) => done.set(t(&lang(), "saved")),
                Err(failed) if failed.is_signed_out() => me.set(None),
                Err(failed) => {
                    error.set(error_word(&lang(), failed.status));
                    bad.set(failed.lines);
                }
            }
        });
    };

    let l = lang();
    let current = kinds.read().iter().find(|kind| kind.id == selected()).cloned();
    rsx! {
        section { class: "editor",
            p { class: "notice notice-danger", role: "alert", hidden: error.read().is_empty(), "{error}" }
            div { class: "pickers", role: "tablist",
                for kind in kinds.read().iter() {
                    button {
                        key: "{kind.id}",
                        class: if selected() == kind.id { "pick pick-on" } else { "pick" },
                        r#type: "button",
                        onclick: { let id = kind.id.clone(); move |_| selected.set(id.clone()) },
                        "{kind.id}"
                    }
                }
            }
            if let Some(kind) = current {
                p { class: "hint", "{kind.file} · {t(&l, reload_key(kind.hot))}" }
                textarea {
                    class: "code",
                    rows: 18,
                    spellcheck: false,
                    readonly: !can_edit,
                    value: "{text}",
                    oninput: move |event| text.set(event.value()),
                }
                if !bad.read().is_empty() {
                    ul { class: "bad-lines",
                        for item in bad.read().iter() {
                            li { key: "{item.line}", strong { "{t(&l, \"line\")} {item.line}" } " {item.reason}" }
                        }
                    }
                }
                p { class: "notice notice-ok", role: "status", hidden: done.read().is_empty(), "{done}" }
                if can_edit {
                    button { class: "primary", r#type: "button", onclick: save, "{t(&l, \"save\")}" }
                } else {
                    p { class: "hint", "{t(&l, \"read_only\")}" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_is_cut_by_part_in_order() {
        let catalog = json!({"settings": [
            {"id": "ips-policy", "part": "ips", "file": "a", "hot": true},
            {"id": "ids-sids", "part": "ids", "file": "b", "hot": false},
            {"id": "ips-never", "part": "ips", "file": "c", "hot": true},
        ]});
        let ids: Vec<String> = kinds_of(&catalog, "ips").into_iter().map(|kind| kind.id).collect();
        assert_eq!(ids, vec!["ips-policy".to_owned(), "ips-never".to_owned()]);
        assert!(kinds_of(&catalog, "av").is_empty());
        assert!(kinds_of(&json!({}), "ips").is_empty());
    }
}
