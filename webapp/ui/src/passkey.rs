//! The browser's side of a passkey: `navigator.credentials`, with the buffers turned into base64url
//! text for the server. `webapp/docs/design.ja.md` stage 14.
//!
//! `navigator.credentials` exists only on a secure page (HTTPS, or localhost). On any
//! other page the call says so instead of failing in a way that looks like a refusal.

use data_encoding::BASE64URL_NOPAD;
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array, JSON};
use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// The browser's refusal as one line: the first line of its `name: message`, without the JsValue wrapper.
fn why(error: JsValue) -> String {
    let text = format!("{error:?}");
    let inner = match text.strip_prefix("JsValue(") {
        Some(rest) => rest,
        None => &text,
    };
    match inner.lines().next() {
        Some(first) => first.to_owned(),
        None => text.clone(),
    }
}

/// The line a screen shows when the browser refused or could not run a passkey call.
pub fn browser_line(lang: &str, why: &str) -> String {
    format!("{} {}", crate::i18n::t(lang, "err_passkey"), why)
}

fn get(target: &JsValue, key: &str) -> Result<JsValue, String> {
    Reflect::get(target, &JsValue::from_str(key)).map_err(why)
}

fn set(target: &JsValue, key: &str, value: &JsValue) -> Result<(), String> {
    Reflect::set(target, &JsValue::from_str(key), value).map(|_| ()).map_err(why)
}

fn bytes_of(text: &str) -> Result<JsValue, String> {
    let raw = BASE64URL_NOPAD.decode(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(JsValue::from(Uint8Array::from(raw.as_slice())))
}

fn text_of(buffer: &JsValue) -> String {
    BASE64URL_NOPAD.encode(&Uint8Array::new(buffer).to_vec())
}

/// Turn the base64url `id` of every entry in a credential list into bytes, in place.
fn bytes_in_ids(list: &JsValue) -> Result<(), String> {
    if !Array::is_array(list) {
        return Ok(());
    }
    for entry in Array::from(list).iter() {
        let id = get(&entry, "id")?;
        let Some(text) = id.as_string() else {
            return Err(String::from("a credential id is not text"));
        };
        set(&entry, "id", &bytes_of(&text)?)?;
    }
    Ok(())
}

/// Call `navigator.credentials.<method>({publicKey})` and wait for the credential.
async fn call(method: &str, public_key: &JsValue) -> Result<JsValue, String> {
    let navigator = get(&js_sys::global(), "navigator")?;
    let container = get(&navigator, "credentials")?;
    if container.is_undefined() || container.is_null() {
        return Err(String::from("this page is not a secure context: a passkey needs HTTPS (or localhost)"));
    }
    let function: Function = get(&container, method)?.dyn_into().map_err(|_| String::from("credentials has no such method"))?;
    let argument = Object::new();
    set(&argument, "publicKey", public_key)?;
    let promise: Promise = function.call1(&container, &argument).map_err(why)?.dyn_into().map_err(|_| String::from("the call did not return a promise"))?;
    JsFuture::from(promise).await.map_err(why)
}

fn parsed(options: &Value) -> Result<JsValue, String> {
    JSON::parse(&options.to_string()).map_err(why)
}

/// Make a passkey for the options the server gave; the answer for `/api/mfa/webauthn/finish`.
pub async fn create(options: &Value) -> Result<Value, String> {
    let public_key = parsed(options)?;
    let challenge = get(&public_key, "challenge")?.as_string().ok_or_else(|| String::from("no challenge"))?;
    set(&public_key, "challenge", &bytes_of(&challenge)?)?;
    let user = get(&public_key, "user")?;
    let handle = get(&user, "id")?.as_string().ok_or_else(|| String::from("no user id"))?;
    set(&user, "id", &bytes_of(&handle)?)?;
    bytes_in_ids(&get(&public_key, "excludeCredentials")?)?;
    let credential = call("create", &public_key).await?;
    let response = get(&credential, "response")?;
    Ok(json!({
        "clientDataJSON": text_of(&get(&response, "clientDataJSON")?),
        "attestationObject": text_of(&get(&response, "attestationObject")?),
    }))
}

/// Sign the challenge in the options with a passkey; the answer for `/api/login/webauthn/finish` (without the ticket).
pub async fn sign(options: &Value) -> Result<Value, String> {
    let public_key = parsed(options)?;
    let challenge = get(&public_key, "challenge")?.as_string().ok_or_else(|| String::from("no challenge"))?;
    set(&public_key, "challenge", &bytes_of(&challenge)?)?;
    bytes_in_ids(&get(&public_key, "allowCredentials")?)?;
    let credential = call("get", &public_key).await?;
    let response = get(&credential, "response")?;
    Ok(json!({
        "id": text_of(&get(&credential, "rawId")?),
        "authenticatorData": text_of(&get(&response, "authenticatorData")?),
        "clientDataJSON": text_of(&get(&response, "clientDataJSON")?),
        "signature": text_of(&get(&response, "signature")?),
    }))
}
