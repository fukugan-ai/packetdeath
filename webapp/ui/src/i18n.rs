//! Japanese and English words. `webapp/docs/design.ja.md`.
//!
//! A key with no word is shown as the key itself, so a missing word is seen on
//! the screen instead of leaving a blank.

use crate::api::ApiError;

/// key, Japanese, English.
const WORDS: &[(&str, &str, &str)] = &[
    ("app", "packetdeath コンソール", "packetdeath console"),
    ("account", "アカウント", "Account"),
    ("password", "パスワード", "Password"),
    ("password_new", "新しいパスワード（12 文字以上）", "New password (12 characters or more)"),
    ("show", "表示する", "Show"),
    ("hide", "隠す", "Hide"),
    ("sign_in", "サインイン", "Sign in"),
    ("register", "管理者を登録", "Register the administrator"),
    ("sign_out", "サインアウト", "Sign out"),
    ("dark", "ダークモード", "Dark mode"),
    ("language", "言語", "Language"),
    ("loading", "読み込み中", "Loading"),
    ("err_401", "アカウントかパスワードが違います", "The account or the password is wrong"),
    ("err_403", "この操作の権限がありません", "You are not allowed to do that"),
    ("err_409", "すでに存在するか、最後の管理者に対する操作です", "It exists already, or it concerns the last administrator"),
    ("err_422", "入力を受け付けられません", "The input was not accepted"),
    ("err_429", "失敗が続いたため、しばらく待ってください", "Too many failures; wait a while"),
    ("password_again", "新しいパスワード（もう一度）", "New password (again)"),
    ("err_mismatch", "2 つのパスワードが一致しません", "The two passwords do not match"),
    ("err_second","確認コードが違います", "The code is wrong"),
    ("err_ticket", "サインインの途中で時間が切れました。パスワードからやり直してください", "The sign-in timed out; start again from the password"),
    ("err_mfa_required", "第二要素を有効にするまで変更できません", "Turn on a second factor before changing anything"),
    ("second_title", "確認コード", "Verification code"),
    ("second_hint", "認証アプリの 6 桁のコード、または回復コード", "The 6-digit code from your authenticator app, or a recovery code"),
    ("second_back", "パスワードに戻る", "Back to the password"),
    ("second_submit", "確認する", "Verify"),
    ("tab_security", "セキュリティ", "Security"),
    ("security", "第二要素", "Second factor"),
    ("mfa_on", "第二要素は有効です", "The second factor is on"),
    ("mfa_off", "第二要素はまだ有効ではありません。パスワードだけでは、運用者と管理者は設定を変えられません", "The second factor is not on yet. With a password alone, operators and administrators cannot change settings"),
    ("mfa_begin", "認証アプリで始める", "Set up an authenticator app"),
    ("mfa_secret", "認証アプリに、この秘密の文字列を入力します（または下のリンクを開きます）", "Enter this secret in your authenticator app (or open the link below)"),
    ("mfa_open_app", "認証アプリで開く", "Open in the authenticator app"),
    ("mfa_code", "アプリに表示された 6 桁のコード", "The 6-digit code the app shows"),
    ("mfa_confirm", "有効にする", "Turn on"),
    ("mfa_codes", "回復コードです。もう表示されません。パスワード管理アプリなどに控えてください。1 つにつき 1 回だけ使えます", "Recovery codes. They are not shown again. Keep them in a password manager. Each works once"),
    ("mfa_saved", "控えました", "I have saved them"),
    ("mfa_banner", "第二要素を有効にするまで、設定の変更と利用者の管理はできません。「セキュリティ」から有効にしてください", "Until a second factor is on you cannot change settings or manage users. Turn it on under Security"),
    ("err_network", "サーバーに届きません", "The server cannot be reached"),
    ("err_error", "失敗しました", "It failed"),
    ("tab_status", "状態", "Status"),
    ("tab_ips", "IPS", "IPS"),
    ("tab_ids", "IDS", "IDS"),
    ("tab_waf", "WAF", "WAF"),
    ("tab_av", "アンチウイルス", "Antivirus"),
    ("tab_users", "利用者", "Users"),
    ("save", "保存", "Save"),
    ("saved", "保存しました", "Saved"),
    ("reload_hot", "1 秒ほどで本体に反映されます", "The running tool picks it up in about a second"),
    ("reload_cold", "次の起動で反映されます", "It takes effect at the next start"),
    ("read_only", "あなたの役では読むだけです", "Your role can read only"),
    ("line", "行", "line"),
    ("waf_title", "WAF の処置", "WAF actions"),
    ("ips_title", "IPS の出来事", "IPS events"),
    ("absent", "まだ記録がありません", "No log yet"),
    ("stale", "Suricata の更新が止まっています", "Suricata has stopped updating"),
    ("not_stale", "Suricata は更新されています", "Suricata is updating"),
    ("total", "合計", "Total"),
    ("unreadable", "読めない行", "Unreadable lines"),
    ("top_rules", "多かった rule", "Most hit rules"),
    ("top_sources", "多かった送信元", "Most frequent sources"),
    ("events", "出来事", "Events"),
    ("name", "名前", "Name"),
    ("role", "役", "Role"),
    ("disabled", "無効", "Disabled"),
    ("create", "作成", "Create"),
    ("remove", "削除", "Delete"),
    ("set_password", "パスワードを再設定", "Reset password"),
    ("enable", "有効にする", "Enable"),
    ("disable", "無効にする", "Disable"),
    ("role_admin", "管理者", "Administrator"),
    ("role_operator", "運用者", "Operator"),
    ("role_viewer", "閲覧者", "Viewer"),
];

fn row(key: &str) -> Option<&'static (&'static str, &'static str, &'static str)> {
    WORDS.iter().find(|row| row.0 == key)
}

/// The word for `key` in `lang` (`ja` or anything else for English).
pub fn t(lang: &str, key: &str) -> String {
    match row(key) {
        Some(found) if lang == "ja" => found.1.to_owned(),
        Some(found) => found.2.to_owned(),
        None => key.to_owned(),
    }
}

/// The word for `<prefix>_<name>` (a tab, a role); a name without a word shows as the key.
pub fn word(lang: &str, prefix: &str, name: &str) -> String {
    t(lang, &format!("{prefix}_{name}"))
}

/// The word for an error status; a status without a word reads as the general failure.
pub fn error_word(lang: &str, status: u16) -> String {
    let key = format!("err_{status}");
    if row(&key).is_some() {
        return t(lang, &key);
    }
    if status == 0 {
        return t(lang, "err_network");
    }
    t(lang, "err_error")
}

/// The line a screen shows for a failed call: the word, the code that names the place it came from, and the server's sentence.
pub fn error_line(lang: &str, failed: &ApiError) -> String {
    let word = match failed.code.as_str() {
        "PD_AUTH_SECOND" => t(lang, "err_second"),
        "PD_AUTH_TICKET" => t(lang, "err_ticket"),
        "PD_AUTH_MFA_REQUIRED" => t(lang, "err_mfa_required"),
        _ => error_word(lang, failed.status),
    };
    format!("{word} [{}] {}", failed.code, failed.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_line_carries_the_code_and_the_servers_sentence() {
        let failed = ApiError { status: 422, code: String::from("PD_USER_PASSWORD"), message: String::from("the password must be 12 to 256 characters"), lines: Vec::new() };
        assert_eq!(error_line("en", &failed), "The input was not accepted [PD_USER_PASSWORD] the password must be 12 to 256 characters");
    }

    #[test]
    fn a_second_step_refusal_does_not_blame_the_password() {
        let failed = ApiError { status: 401, code: String::from("PD_AUTH_SECOND"), message: String::from("the code is wrong"), lines: Vec::new() };
        assert_eq!(error_line("en", &failed), "The code is wrong [PD_AUTH_SECOND] the code is wrong");
    }

    #[test]
    fn every_key_is_unique_and_has_both_languages() {
        let mut keys: Vec<&str> = WORDS.iter().map(|row| row.0).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len());
        assert!(WORDS.iter().all(|row| !row.1.is_empty() && !row.2.is_empty()));
    }

    #[test]
    fn a_missing_key_shows_as_itself() {
        assert_eq!(t("ja", "no_such_key"), "no_such_key");
        assert_eq!(t("ja", "save"), "保存");
        assert_eq!(t("en", "save"), "Save");
    }

    #[test]
    fn an_error_status_has_a_word() {
        assert_eq!(error_word("en", 0), "The server cannot be reached");
        assert_eq!(error_word("en", 429), "Too many failures; wait a while");
        assert_eq!(error_word("en", 500), "It failed");
    }
}
