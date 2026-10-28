//! The status screen. `webapp/docs/design.ja.md`.
//!
//! The numbers are the server's: the same ones `waf-report` and `ips-report`
//! print. A log that does not exist yet is shown as absent, not as zero.

use dioxus::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::i18n::{error_line, t};
use crate::{api, Me};

/// A JSON object of counts as sorted rows, biggest first.
pub fn rows_of_map(value: &Value) -> Vec<(String, u64)> {
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for (key, count) in map {
        if let Some(n) = count.as_u64() {
            rows.push((key.clone(), n));
        }
    }
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// A JSON array of `{key, count}` as rows.
pub fn rows_of_pairs(value: &Value) -> Vec<(String, u64)> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for item in items {
        let key = item.get("key").and_then(Value::as_str);
        let count = item.get("count").and_then(Value::as_u64);
        if let (Some(key), Some(count)) = (key, count) {
            rows.push((key.to_owned(), count));
        }
    }
    rows
}

/// The word for Suricata's state in a status answer.
pub fn stale_key(body: &Value) -> &'static str {
    if body["ips"]["stale"] == true {
        "stale"
    } else {
        "not_stale"
    }
}

#[component]
fn Table(title: String, rows: Vec<(String, u64)>) -> Element {
    rsx! {
        section { class: "card",
            h3 { "{title}" }
            table { class: "grid",
                tbody {
                    for (key, count) in rows.iter() {
                        tr { key: "{key}", td { class: "k", "{key}" } td { class: "n", "{count}" } }
                    }
                }
            }
        }
    }
}

#[component]
pub fn Status(lang: Signal<String>, me: Signal<Option<Me>>) -> Element {
    let mut data = use_signal(|| None::<Value>);
    let mut error = use_signal(String::new);
    use_effect(move || {
        spawn_local(async move {
            match api::get("/api/status").await {
                Ok(body) => data.set(Some(body)),
                Err(failed) if failed.is_signed_out() => me.set(None),
                Err(failed) => error.set(error_line(&lang(), &failed)),
            }
        });
    });
    let l = lang();
    let found = data.read().clone();
    rsx! {
        section { class: "status",
            p { class: "notice notice-danger", role: "alert", hidden: error.read().is_empty(), "{error}" }
            if let Some(body) = found {
                div { class: "cols",
                    div { class: "col",
                        h2 { "{t(&l, \"waf_title\")}" }
                        if body["waf"]["present"] == true {
                            p { class: "big", "{t(&l, \"total\")}: ", strong { "{body[\"waf\"][\"total\"]}" } }
                            p { "{t(&l, \"unreadable\")}: {body[\"waf\"][\"unreadable\"]}" }
                            Table { title: t(&l, "events"), rows: rows_of_map(&body["waf"]["by_action"]) }
                            Table { title: t(&l, "top_rules"), rows: rows_of_pairs(&body["waf"]["top_rules"]) }
                            Table { title: t(&l, "top_sources"), rows: rows_of_pairs(&body["waf"]["top_sources"]) }
                        } else {
                            p { class: "absent", "{t(&l, \"absent\")}" }
                        }
                    }
                    div { class: "col",
                        h2 { "{t(&l, \"ips_title\")}" }
                        if body["ips"]["present"] == true {
                            p { class: if body["ips"]["stale"] == true { "notice notice-danger" } else { "notice notice-ok" },
                                "{t(&l, stale_key(&body))}"
                            }
                            Table { title: t(&l, "events"), rows: rows_of_map(&body["ips"]["events"]) }
                        } else {
                            p { class: "absent", "{t(&l, \"absent\")}" }
                        }
                    }
                }
            } else if error.read().is_empty() {
                p { class: "absent", "{t(&l, \"loading\")}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_map_becomes_rows_biggest_first_and_ties_by_name() {
        let rows = rows_of_map(&json!({"b": 2, "a": 2, "c": 9}));
        assert_eq!(rows, vec![("c".to_owned(), 9), ("a".to_owned(), 2), ("b".to_owned(), 2)]);
    }

    #[test]
    fn pairs_without_both_fields_are_left_out() {
        let rows = rows_of_pairs(&json!([{"key": "x", "count": 3}, {"key": "y"}, {"count": 1}]));
        assert_eq!(rows, vec![("x".to_owned(), 3)]);
    }

    #[test]
    fn something_that_is_not_a_map_or_an_array_has_no_rows() {
        assert!(rows_of_map(&json!(3)).is_empty());
        assert!(rows_of_pairs(&json!({"a": 1})).is_empty());
    }
}
