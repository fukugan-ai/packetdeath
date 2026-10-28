//! Offer the browser's password manager the account and password after a successful sign-in.
//! `webapp/docs/design.ja.md`, the sign-in screen.
//!
//! The sign-in posts with `fetch`, and with a second step the password field is gone
//! before the last answer, so the browser has nothing in a form to save. The
//! Credential Management API (`PasswordCredential`, Chromium; secure context only) hands the pair over
//! directly. Where the API is missing the call says so and the form's own `autocomplete`
//! attributes remain the way to save.

use js_sys::{Function, Object, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

fn missing(what: &str) -> String {
    format!("{what} is not available in this browser")
}

fn get(target: &JsValue, key: &str) -> Result<JsValue, String> {
    Reflect::get(target, &JsValue::from_str(key)).map_err(|e| format!("{e:?}"))
}

fn pair(name: &str, password: &str) -> Result<Object, String> {
    let data = Object::new();
    Reflect::set(&data, &JsValue::from_str("id"), &JsValue::from_str(name)).map_err(|e| format!("{e:?}"))?;
    Reflect::set(&data, &JsValue::from_str("password"), &JsValue::from_str(password)).map_err(|e| format!("{e:?}"))?;
    Ok(data)
}

/// Hand `name` and `password` to the browser's password manager.
pub async fn offer(name: &str, password: &str) -> Result<(), String> {
    let global = js_sys::global();
    let ctor: Function = get(&global, "PasswordCredential")?.dyn_into().map_err(|_| missing("PasswordCredential"))?;
    let container = get(&get(&global, "navigator")?, "credentials")?;
    if container.is_undefined() || container.is_null() {
        return Err(missing("navigator.credentials"));
    }
    let store: Function = get(&container, "store")?.dyn_into().map_err(|_| missing("credentials.store"))?;
    let data = JsValue::from(pair(name, password)?);
    let args = js_sys::Array::of1(&data);
    let credential = Reflect::construct(&ctor, &args).map_err(|e| format!("{e:?}"))?;
    let promise: js_sys::Promise = store.call1(&container, &credential).map_err(|e| format!("{e:?}"))?.dyn_into().map_err(|_| String::from("store did not return a promise"))?;
    JsFuture::from(promise).await.map(|_| ()).map_err(|e| format!("{e:?}"))
}
