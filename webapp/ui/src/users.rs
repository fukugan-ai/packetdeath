//! The users screen, for administrators. `webapp/docs/design.ja.md`.
//!
//! Every rule (who may do it, the last administrator staying) is the
//! server's; the screen shows the refusal it gets.

use dioxus::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::generate;
use crate::i18n::{error_line, t, word};
use crate::passkey;
use crate::Me;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Row {
    pub name: String,
    pub role: String,
    pub disabled: bool,
}

pub fn rows_of(body: &Value) -> Vec<Row> {
    let Some(items) = body.get("users").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for item in items {
        if let Ok(row) = serde_json::from_value::<Row>(item.clone()) {
            rows.push(row);
        }
    }
    rows
}

const ROLES: [&str; 3] = ["admin", "operator", "viewer"];

#[component]
pub fn Users(lang: Signal<String>, user: Me, me: Signal<Option<Me>>) -> Element {
    let mut rows = use_signal(Vec::<Row>::new);
    let mut error = use_signal(String::new);
    let mut new_name = use_signal(String::new);
    let mut new_password = use_signal(String::new);
    let mut new_confirm = use_signal(String::new);
    let mut show_new = use_signal(|| false);
    let mut new_role = use_signal(|| String::from("viewer"));
    let csrf = user.csrf.clone();

    let reload = move || {
        spawn_local(async move {
            match api::get("/api/users").await {
                Ok(body) => rows.set(rows_of(&body)),
                Err(failed) if failed.is_signed_out() => me.set(None),
                Err(failed) => error.set(error_line(&lang(), &failed)),
            }
        });
    };
    use_effect(reload);

    // One change to the directory, then the list again.
    let act = use_callback(move |(method, path, body): (&'static str, String, Value)| {
        let csrf = csrf.clone();
        error.set(String::new());
        spawn_local(async move {
            match api::send(method, &path, &csrf, &body).await {
                Ok(_) => reload(),
                Err(failed) if failed.is_signed_out() => me.set(None),
                Err(failed) => error.set(error_line(&lang(), &failed)),
            }
        });
    });

    let l = lang();
    let create = move |event: FormEvent| {
        event.prevent_default();
        if new_password() != new_confirm() {
            error.set(t(&lang(), "err_mismatch"));
            return;
        }
        new_confirm.set(String::new());
        let body = json!({"name": new_name(), "password": new_password(), "role": new_role()});
        act.call(("POST", String::from("/api/users"), body));
        new_password.set(String::new());
        new_name.set(String::new());
    };
    rsx! {
        section { class: "users",
            p { class: "notice notice-danger", role: "alert", hidden: error.read().is_empty(), "{error}" }
            table { class: "grid wide",
                thead { tr { th { "{t(&l, \"name\")}" } th { "{t(&l, \"role\")}" } th { "{t(&l, \"disabled\")}" } th {} } }
                tbody {
                    for row in rows.read().iter() {
                        UserRow { key: "{row.name}", row: row.clone(), lang, act }
                    }
                }
            }
            form { class: "card create", onsubmit: create,
                input { r#type: "text", id: "new-username", name: "username", value: "{new_name}", placeholder: "{t(&l, \"name\")}", maxlength: 128, required: true, autocomplete: "username",
                    oninput: move |event| new_name.set(event.value()) }
                button { class: "quiet", r#type: "button", id: "new-user-generate",
                    onclick: move |_| match generate::password() {
                        Ok(fresh) => { new_password.set(fresh.clone()); new_confirm.set(fresh); show_new.set(true); }
                        Err(why) => error.set(passkey::browser_line(&lang(), &why)),
                    },
                    "{t(&l, \"password_generate\")}" }
                input { r#type: if show_new() { "text" } else { "password" }, id: "new-user-password", name: "new-password", value: "{new_password}", placeholder: "{t(&l, \"password_new\")}", minlength: "128", required: true, autocomplete: "new-password",
                    oninput: move |event| new_password.set(event.value()) }
                input { r#type: if show_new() { "text" } else { "password" }, id: "new-user-password-confirm", name: "new-password-confirm", value: "{new_confirm}", placeholder: "{t(&l, \"password_again\")}", minlength: "128", required: true, autocomplete: "new-password",
                    oninput: move |event| new_confirm.set(event.value()) }
                select { value: "{new_role}", onchange: move |event| new_role.set(event.value()),
                    for role in ROLES { option { key: "{role}", value: "{role}", "{word(&l, \"role\", role)}" } }
                }
                button { class: "primary", r#type: "submit", "{t(&l, \"create\")}" }
            }
        }
    }
}

#[component]
fn UserRow(row: Row, lang: Signal<String>, act: Callback<(&'static str, String, Value)>) -> Element {
    let mut password = use_signal(String::new);
    let mut shown = use_signal(|| false);
    let l = lang();
    let path = format!("/api/users/{}", row.name);
    let (role_path, off_path, pass_path, drop_path) = (path.clone(), path.clone(), path.clone(), path);
    let toggled = !row.disabled;
    let switch_key = if row.disabled { "enable" } else { "disable" };
    rsx! {
        tr {
            td { "{row.name}" }
            td {
                select { value: "{row.role}",
                    onchange: move |event| act.call(("PATCH", role_path.clone(), json!({"role": event.value()}))),
                    for role in ROLES { option { key: "{role}", value: "{role}", selected: row.role == role, "{word(&l, \"role\", role)}" } }
                }
            }
            td { "{row.disabled}" }
            td { class: "actions",
                button { class: "quiet", r#type: "button",
                    onclick: move |_| act.call(("PATCH", off_path.clone(), json!({"disabled": toggled}))),
                    "{t(&l, switch_key)}" }
                form { class: "actions",
                    onsubmit: move |event| { event.prevent_default(); act.call(("PATCH", pass_path.clone(), json!({"password": password()}))); password.set(String::new()); },
                    input { r#type: "text", name: "username", value: "{row.name}", autocomplete: "username", hidden: true, readonly: true }
                    button { class: "quiet", r#type: "button",
                        onclick: move |_| { if let Ok(fresh) = generate::password() { password.set(fresh); shown.set(true); } },
                        "{t(&l, \"password_generate\")}" }
                    input { r#type: if shown() { "text" } else { "password" }, name: "new-password", value: "{password}", placeholder: "{t(&l, \"password_new\")}", minlength: "128", required: true, autocomplete: "new-password",
                        oninput: move |event| password.set(event.value()) }
                    button { class: "quiet", r#type: "submit", "{t(&l, \"set_password\")}" }
                }
                button { class: "quiet danger", r#type: "button",
                    onclick: move |_| act.call(("DELETE", drop_path.clone(), json!({}))),
                    "{t(&l, \"remove\")}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_read_and_a_row_without_all_fields_is_left_out() {
        let body = json!({"users": [
            {"name": "alice", "role": "admin", "disabled": false, "created": 1},
            {"name": "broken"},
        ]});
        let rows = rows_of(&body);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "alice");
        assert!(rows_of(&json!({})).is_empty());
    }
}
