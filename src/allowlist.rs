//! 「当たっても通す」allowlist。`docs/design.md`「判定を差し込む口」節が正本。
//!
//! 形式・照合方式は `src/blocklist.rs` に倣う。1行1 domain。`#` で始まる行は
//! 無視。`example.org` は `example.org` と `*.example.org` に当たる（サフィックス
//! 一致。`Blocklist::matches` と同じ意味）。
//!
//! **allowlist は blocklist より先に判定される。**`judge.rs` の
//! `run_judges_with_allowlist` が、SNI が allowlist に当たれば他の判定器を
//! 1つも評価せず `pass` を返す（`docs/design.md`「判定を差し込む口」）。
//!
//! **外部が更新する allowlist を、動作の gate にしない。**file が読めなくても
//! `Allowlist::empty()` へ倒す（呼び出し側の責務。`blocklist.rs` と同じ判断）。

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

/// allowlist に当たる domain の集合。完全一致とサブドメイン一致の両方を持つ。
#[derive(Debug, Default)]
pub struct Allowlist {
    /// 小文字化した domain（`example.org` の形。先頭に `*.` は付けない）。
    domains: HashSet<String>,
}

#[derive(Debug)]
pub enum AllowlistError {
    Io(std::io::Error),
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(
                f,
                "{}",
                crate::i18n::allowlist_io_failed(crate::i18n::locale(), e)
            ),
        }
    }
}

impl std::error::Error for AllowlistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for AllowlistError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl Allowlist {
    /// 何にも当たらない空の allowlist（`--allowlist` 未指定時の既定値。
    /// 何も救わない＝従来どおりの挙動）。
    pub fn empty() -> Self {
        Self {
            domains: HashSet::new(),
        }
    }

    /// `path` から allowlist を読む。
    pub fn load(path: &Path) -> Result<Self, AllowlistError> {
        let content = std::fs::read_to_string(path)?;
        let list = Self::parse(&content);
        crate::flow::service_log(&format!(
            "packetdeath: [info] {}",
            crate::i18n::allowlist_loaded(
                crate::i18n::locale(),
                path.display(),
                list.domains.len()
            )
        ));
        Ok(list)
    }

    /// 1行1 domain、`#` で始まる行は無視する形式を読む。
    pub fn parse(content: &str) -> Self {
        let domains = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_ascii_lowercase)
            .collect();
        Self { domains }
    }

    /// 登録済み domain の数。reload 前後の差分を log に出すためだけに使う。
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// clippy `len_without_is_empty` を満たすための対。
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// `host` が allowlist に当たるか。`example.org` は `example.org` 自体と
    /// `*.example.org`（任意深さのサブドメイン）の両方に当たる
    /// （`Blocklist::matches` と同じサフィックス一致）。
    pub fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        if self.domains.contains(&host) {
            return true;
        }
        let mut rest = host.as_str();
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if self.domains.contains(rest) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_matches_nothing() {
        let al = Allowlist::empty();
        assert!(!al.matches("example.org"));
        assert!(!al.matches(""));
    }

    #[test]
    fn len_counts_parsed_domains() {
        let al = Allowlist::parse("a.example\nb.example\n");
        assert_eq!(al.len(), 2);
        assert!(!al.is_empty());
        assert!(Allowlist::empty().is_empty());
    }

    #[test]
    fn parse_ignores_comment_and_blank_lines() {
        let al = Allowlist::parse("# comment\n\nexample.org\n  # indented comment\n");
        assert!(al.matches("example.org"));
        assert!(!al.matches("# comment"));
    }

    #[test]
    fn exact_domain_matches() {
        let al = Allowlist::parse("example.org\n");
        assert!(al.matches("example.org"));
    }

    #[test]
    fn subdomain_matches_wildcard() {
        let al = Allowlist::parse("example.org\n");
        assert!(al.matches("a.example.org"));
        assert!(al.matches("deep.a.example.org"));
    }

    #[test]
    fn unrelated_domain_with_shared_suffix_does_not_match() {
        let al = Allowlist::parse("example.org\n");
        assert!(!al.matches("notexample.org"));
    }

    #[test]
    fn match_is_case_insensitive() {
        let al = Allowlist::parse("Example.ORG\n");
        assert!(al.matches("EXAMPLE.org"));
    }

    #[test]
    fn unrelated_domain_does_not_match() {
        let al = Allowlist::parse("ok.example\n");
        assert!(!al.matches("example.com"));
    }
}
