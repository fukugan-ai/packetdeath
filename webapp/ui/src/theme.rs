//! Light or dark, and the language. `webapp/docs/design.ja.md`.
//!
//! Both are remembered per browser. A browser that refuses storage still
//! works; the choice then lasts until the page is closed.

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn root() -> Option<web_sys::Element> {
    web_sys::window()?.document()?.document_element()
}

fn stored(key: &str) -> Option<String> {
    storage()?.get_item(key).ok()?
}

fn remember(key: &str, value: &str) {
    if let Some(store) = storage() {
        if store.set_item(key, value).is_err() {
            web_sys::console::warn_1(&"the choice could not be stored".into());
        }
    }
}

/// The remembered theme; dark when nothing is remembered, as the stylesheet's first paint is.
pub fn theme() -> String {
    // DEFAULT: a first visit has no remembered theme, and the page is drawn dark before this runs.
    let mut chosen = String::from("dark");
    if let Some(found) = stored("pd-theme") {
        if found == "light" || found == "dark" {
            chosen = found;
        }
    }
    chosen
}

pub fn set_theme(value: &str) {
    remember("pd-theme", value);
    apply_theme(value);
}

pub fn apply_theme(value: &str) {
    if let Some(element) = root() {
        if element.set_attribute("data-theme", value).is_err() {
            web_sys::console::warn_1(&"the theme could not be applied".into());
        }
    }
}

/// The remembered language, or the browser's when it is Japanese, or English.
pub fn lang() -> String {
    if let Some(found) = stored("pd-lang") {
        if found == "ja" || found == "en" {
            return found;
        }
    }
    // DEFAULT: with no remembered language the browser's own decides, and a browser that is not Japanese reads English.
    let mut chosen = String::from("en");
    let browser = web_sys::window().and_then(|window| window.navigator().language());
    if browser.is_some_and(|tag| tag.starts_with("ja")) {
        chosen = String::from("ja");
    }
    chosen
}

pub fn set_lang(value: &str) {
    remember("pd-lang", value);
    apply_lang(value);
}

pub fn apply_lang(value: &str) {
    if let Some(element) = root() {
        if element.set_attribute("lang", value).is_err() {
            web_sys::console::warn_1(&"the language could not be applied".into());
        }
    }
}
