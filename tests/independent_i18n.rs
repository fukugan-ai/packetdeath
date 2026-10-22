//! 独立検算。log 出力も含めて i18n が locale で切り替わることの受入。
//! `src/i18n.rs` の公開 API
//! （[`packetdeath::i18n::all_message_samples`] と、実際にビルドした
//! `packetdeath` binary）だけを使う。
//!
//! # `unwrap()` / `expect()` を使わない
//! 各 test は `Result<(), Box<dyn std::error::Error>>` を返し、`?` で伝播する。

use packetdeath::i18n;
use std::error::Error;
use std::path::PathBuf;
use std::process::{Command, Stdio};

type TestResult = Result<(), Box<dyn Error>>;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_packetdeath"))
}

/// 引数なしで起動する（usage banner が `[error]` で stderr へ出て、
/// exit failure になる。`src/main.rs::main` の契約）。`LANG` / `LC_ALL` を
/// 明示的に制御するため、親 process の環境は継承しつつ `env_clear` は
/// **使わない**（`PATH` 等まで消すと `Command::new` 自体が失敗し得る）。
fn run_with_locale(lang: Option<&str>) -> Result<String, Box<dyn Error>> {
    let mut cmd = Command::new(bin());
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .env_remove("LC_ALL");
    match lang {
        Some(v) => {
            cmd.env("LANG", v);
        }
        None => {
            cmd.env_remove("LANG");
        }
    }
    let output = cmd.output()?;
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// 日本語（ひらがな・カタカナ・漢字）を1文字でも含むか。
fn contains_japanese(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '\u{3040}'..='\u{30ff}' | '\u{4e00}'..='\u{9faf}'))
}

#[test]
fn lang_ja_produces_japanese_usage_banner_and_locale_log() -> TestResult {
    let stderr = run_with_locale(Some("ja_JP.UTF-8"))?;
    assert!(
        stderr.contains("locale=ja"),
        "起動時の locale log に ja が出ない: {stderr:?}"
    );
    assert!(
        stderr.contains("使い方:"),
        "LANG=ja_JP.UTF-8 なのに日本語の usage banner が出ない: {stderr:?}"
    );
    assert!(
        !stderr.contains("usage:"),
        "LANG=ja_JP.UTF-8 なのに英語の usage banner が混ざっている: {stderr:?}"
    );
    Ok(())
}

#[test]
fn lang_en_produces_english_usage_banner_and_locale_log() -> TestResult {
    let stderr = run_with_locale(Some("en_US.UTF-8"))?;
    assert!(
        stderr.contains("locale=en"),
        "起動時の locale log に en が出ない: {stderr:?}"
    );
    assert!(
        stderr.contains("usage:"),
        "LANG=en_US.UTF-8 なのに英語の usage banner が出ない: {stderr:?}"
    );
    assert!(
        !contains_japanese(&stderr),
        "LANG=en_US.UTF-8 なのに日本語が混ざっている: {stderr:?}"
    );
    Ok(())
}

#[test]
fn unset_lang_defaults_to_english() -> TestResult {
    let stderr = run_with_locale(None)?;
    assert!(
        stderr.contains("locale=en"),
        "LANG 未設定なのに既定が en になっていない: {stderr:?}"
    );
    assert!(
        stderr.contains("usage:"),
        "LANG 未設定なのに英語の usage banner が出ない: {stderr:?}"
    );
    Ok(())
}

#[test]
fn unsupported_lang_fr_falls_back_to_english_without_crashing() -> TestResult {
    let stderr = run_with_locale(Some("fr_FR.UTF-8"))?;
    assert!(
        stderr.contains("locale=en"),
        "未対応の LANG=fr_FR.UTF-8 なのに en へ倒れていない: {stderr:?}"
    );
    assert!(
        stderr.contains("usage:"),
        "未対応の LANG=fr_FR.UTF-8 なのに英語の usage banner が出ない（落ちずに動いた証拠が無い）: {stderr:?}"
    );
    Ok(())
}

/// **翻訳漏れの機械検査（同じ key が両方の言語に在ることを機械で検査する）。**
///
/// `src/i18n.rs` の「メッセージ関数」（`locale` / `log_detected_locale` /
/// `all_message_samples` を除く `pub fn`）の総数と、
/// `all_message_samples()` が返す件数を突き合わせる。新しい `pub fn` を
/// 足して `all_message_samples` に登録し忘れると、この test が件数の
/// 不一致で落ちる。
#[test]
fn every_pub_message_fn_has_a_sample() -> TestResult {
    let src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/i18n.rs");
    let src = std::fs::read_to_string(&src_path)?;
    let pub_fn_count = src
        .lines()
        .filter(|line| line.trim_start().starts_with("pub fn "))
        .count();
    // メッセージ関数ではない3つ（locale 判定の入口・起動時 log・この test が
    // 使うサンプル集そのもの）を除く。
    let non_message_fns = 3;
    let message_fn_count = pub_fn_count
        .checked_sub(non_message_fns)
        .ok_or("src/i18n.rs の pub fn が3個未満だった（locale/log_detected_locale/all_message_samples より少ない）")?;

    let samples = i18n::all_message_samples();
    assert_eq!(
        message_fn_count,
        samples.len(),
        "src/i18n.rs の pub fn 数（メッセージ関数のみ、{message_fn_count}）と \
         all_message_samples() の件数（{}）が一致しない。\
         新しい関数を足したら all_message_samples にも1行 足すこと",
        samples.len()
    );
    Ok(())
}

/// 全メッセージ sample で ja と en が異なる文字列であること
/// （`src/i18n.rs` 内部 unit test の追認。独立 test 側からも確かめる）。
#[test]
fn all_samples_differ_between_ja_and_en() -> TestResult {
    let samples = i18n::all_message_samples();
    assert!(!samples.is_empty(), "all_message_samples が空だった");
    for (name, ja, en) in &samples {
        assert_ne!(ja, en, "{name} で ja と en が同じ文字列になっている");
    }
    Ok(())
}

/// **翻訳漏れの、より強い検査。**`ja != en` だけでは「両方 英語のまま、
/// 末尾の句読点だけ違う」ような手抜き実装を見逃す。ja 側には日本語文字が
/// 1文字以上、en 側には日本語文字が0文字であることまで確かめる。
#[test]
fn ja_samples_contain_japanese_and_en_samples_do_not() -> TestResult {
    let samples = i18n::all_message_samples();
    for (name, ja, en) in &samples {
        assert!(
            contains_japanese(ja),
            "{name} の ja 版に日本語が1文字も無い（英語のまま放置されている疑い）: {ja:?}"
        );
        assert!(
            !contains_japanese(en),
            "{name} の en 版に日本語が混ざっている: {en:?}"
        );
    }
    Ok(())
}
