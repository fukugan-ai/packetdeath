//! 段階2「遮断」の blocklist。`docs/design.md`「名前と置き場」の
//! blocklist 形式が正本。
//!
//! 形式は1行1 domain。`#` で始まる行は無視。`example.org` は `example.org` と
//! `*.example.org` に当たる（Suricata の `dotprefix` と同じ意味）。
//! EasyList の構文は読まない。
//!
//! **外部が更新する blocklist を、動作の gate にしない。**file が読めなくても
//! `Blocklist::empty()` へ倒して素通しのまま動き続ける（呼び出し側の責務）。

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// blocklist に当たる domain の集合。完全一致とサブドメイン一致の両方を持つ。
#[derive(Debug, Default, Clone)]
pub struct Blocklist {
    /// 小文字化した domain（`example.org` の形。先頭に `*.` は付けない）。
    domains: HashSet<String>,
}

#[derive(Debug)]
pub enum BlocklistError {
    Io(std::io::Error),
}

impl fmt::Display for BlocklistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(
                f,
                "{}",
                crate::i18n::blocklist_io_failed(crate::i18n::locale(), e)
            ),
        }
    }
}

impl std::error::Error for BlocklistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for BlocklistError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl Blocklist {
    /// 何にも当たらない空の blocklist（PK-10 の陰性対照）。
    pub fn empty() -> Self {
        Self {
            domains: HashSet::new(),
        }
    }

    /// `path` から blocklist を読む。
    pub fn load(path: &Path) -> Result<Self, BlocklistError> {
        let content = std::fs::read_to_string(path)?;
        let list = Self::parse(&content);
        crate::flow::service_log(&format!(
            "packetdeath: [info] {}",
            crate::i18n::blocklist_loaded(
                crate::i18n::locale(),
                path.display(),
                list.domains.len()
            )
        ));
        Ok(list)
    }

    /// `paths` の各 file を [`load`](Self::load) で読む（`--blocklist` の複数指定）。
    /// 読めなかった file は `[warn]` を出して空の list にする（fail-open）。
    /// 空の list も返すので、後から file が現れても同じ path で読み直せる。
    pub fn load_all(paths: &[PathBuf]) -> Vec<(PathBuf, Self)> {
        paths
            .iter()
            .map(|path| {
                let list = match Self::load(path) {
                    Ok(list) => list,
                    Err(e) => {
                        crate::flow::service_log(&format!(
                            "packetdeath: [warn] {}",
                            crate::i18n::blocklist_load_failed_empty(
                                crate::i18n::locale(),
                                path.display(),
                                e
                            )
                        ));
                        Self::empty()
                    }
                };
                (path.clone(), list)
            })
            .collect()
    }

    /// `lists` の和集合。
    pub fn union<'a>(lists: impl IntoIterator<Item = &'a Blocklist>) -> Self {
        let mut domains = HashSet::new();
        for list in lists {
            domains.extend(list.domains.iter().cloned());
        }
        Self { domains }
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

    /// `host` が blocklist に当たるか。`example.org` は `example.org` 自体と
    /// `*.example.org`（任意深さのサブドメイン）の両方に当たる。
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
    fn empty_blocklist_matches_nothing() {
        // テスト項目1。
        let bl = Blocklist::empty();
        assert!(!bl.matches("example.org"));
        assert!(!bl.matches(""));
    }

    #[test]
    fn len_counts_parsed_domains() {
        let bl = Blocklist::parse("a.example\nb.example\n");
        assert_eq!(bl.len(), 2);
        assert!(!bl.is_empty());
        assert!(Blocklist::empty().is_empty());
    }

    #[test]
    fn union_matches_what_either_side_matches() {
        let a = Blocklist::parse("a.example\n");
        let b = Blocklist::parse("b.example\n");
        let both = Blocklist::union([&a, &b]);
        assert!(both.matches("a.example"));
        assert!(both.matches("sub.b.example"));
        assert!(!both.matches("c.example"));
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn union_of_nothing_is_empty() {
        assert!(Blocklist::union([]).is_empty());
    }

    #[test]
    fn load_all_keeps_a_slot_for_an_unreadable_file() {
        let missing = PathBuf::from("/nonexistent/packetdeath-blocklist-load-all.txt");
        let loaded = Blocklist::load_all(std::slice::from_ref(&missing));
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, missing);
        assert!(loaded[0].1.is_empty());
    }

    #[test]
    fn parse_ignores_comment_and_blank_lines() {
        // テスト項目5。
        let bl = Blocklist::parse("# comment\n\nexample.org\n  # indented comment\n");
        assert!(bl.matches("example.org"));
        assert!(!bl.matches("# comment"));
    }

    #[test]
    fn exact_domain_matches() {
        let bl = Blocklist::parse("example.org\n");
        assert!(bl.matches("example.org"));
    }

    #[test]
    fn subdomain_matches_wildcard() {
        // テスト項目4。
        let bl = Blocklist::parse("example.org\n");
        assert!(bl.matches("a.example.org"));
        assert!(bl.matches("deep.a.example.org"));
    }

    #[test]
    fn unrelated_domain_with_shared_suffix_does_not_match() {
        // テスト項目4。`notexample.org` は `example.org` に当たらない。
        let bl = Blocklist::parse("example.org\n");
        assert!(!bl.matches("notexample.org"));
    }

    #[test]
    fn match_is_case_insensitive() {
        let bl = Blocklist::parse("Example.ORG\n");
        assert!(bl.matches("EXAMPLE.org"));
    }

    #[test]
    fn unrelated_domain_does_not_match() {
        // テスト項目2。
        let bl = Blocklist::parse("ads.example\n");
        assert!(!bl.matches("example.com"));
    }
}
