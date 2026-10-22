//! `packetdeath filterlist --in <path> --out <path>`。EasyList 形式の
//! adblock filter list を、`src/blocklist.rs` が読む1行1 domain の
//! blocklist 形式へ変換する。`docs/design.md`「EasyList からの変換」節が正本。
//!
//! **EasyList の構文は原理的に部分しか読めない。**SNI 照合は TLS を復号しない
//! ので、通信の宛先 domain しか見えない。要素隠し（`##`）、path 指定
//! （`/ads/banner.gif`）、`$third-party` 等の一部の修飾子は、HTTPS の URL や
//! Referer が要る判定であり、SNI だけでは再現できない。これらは変換時に
//! 意図して捨てる（`docs/design.md`「SNI 方式で原理的に効かないもの」）。
//!
//! この module は file I/O を持たない（`convert` は文字列を受け取り文字列を
//! 返すだけ）。file の読み書きは `main.rs` が担う。
//!
//! # `packetdeath allowlist-convert --in <path> --out <path>`（allowlist 変換）
//!
//! 「当たっても通す」allowlist（`src/allowlist.rs`）を公開 list から作る道具。
//! **network へ出ない。**利用者が落とした file を読むだけである
//! （`docs/design.md`「制約」の「rule と pktmon は利用者が入れる」と同じ思想）。
//! 3つの形式を [`detect_allow_source`] が自動判定して読む。
//!
//! | 形式 | 例 | 変換 |
//! |---|---|---|
//! | Microsoft 公式 API の JSON | `[{"urls":["*.auth.microsoft.com", ...]}, ...]` | `urls` を集め、`*.` を剥がす |
//! | 平文 1行1 domain | `1drv.com` | そのまま（`#` コメントは無視） |
//! | Adblock Plus の allow rule | `@@||example.com^` | `example.com` を取り出す |
//!
//! **`*` が先頭以外に在るもの（`foo.*.example.com` や `*cdn.example.com` の
//! ように `*.` の形でない先頭ワイルドカード）は捨てる。**`Allowlist::matches`
//! はサフィックス一致（`example.com` は `example.com` と `*.example.com` の
//! 両方に当たる）しか表現できず、任意の位置のワイルドカードを再現できない
//! ため（`src/blocklist.rs:87-93` と同じ理由）。捨てた件数は
//! [`AllowStats::discarded`] に残る。

use serde::Deserialize;
use std::collections::BTreeSet;
use std::collections::HashSet;

/// `$` 修飾子のうち、domain 単位で当たっても実害が小さいとして採用するもの
/// （`docs/design.md`「EasyList からの変換」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModifierKind {
    ThirdParty,
    ThreeP,
    All,
    Document,
}

impl ModifierKind {
    fn parse(modifier: &str) -> Option<Self> {
        match modifier {
            "third-party" => Some(Self::ThirdParty),
            "3p" => Some(Self::ThreeP),
            "all" => Some(Self::All),
            "document" => Some(Self::Document),
            _ => None,
        }
    }
}

/// `||` で始まる network rule（`@@` を剥いた後の残り）の分類結果。
#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkOutcome {
    /// 採用できる純 domain。`modifier` は `$` 修飾子が在り、かつ採用可能
    /// だったときだけ `Some`。
    Domain {
        host: String,
        modifier: Option<ModifierKind>,
    },
    /// 採用できない `$` 修飾子（`third-party`/`3p`/`all`/`document` 以外）。
    ModifierDiscarded,
    /// path 指定を含む（`/` を含む）。
    Path,
    /// `||` で始まらない（この module が読める network rule の形ではない）。
    NotNetworkRule,
    /// `||` の直後に domain 文字が1つも続かない（壊れた行）。
    Malformed,
}

/// 先頭から ASCII の domain 文字（`a-zA-Z0-9.-`）が続く部分と、残りを返す。
fn take_domain_token(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .unwrap_or(s.len());
    s.split_at(end)
}

/// `@@` を既に剥いた（か、剥ぐ必要が無い）残りの行を分類する。
/// `*` と `~` の判定は呼び出し側（`classify_line`）が先に行う。
fn classify_network_rule(rest: &str) -> NetworkOutcome {
    let Some(body) = rest.strip_prefix("||") else {
        return NetworkOutcome::NotNetworkRule;
    };
    let (domain_part, remainder) = take_domain_token(body);
    if domain_part.is_empty() {
        return NetworkOutcome::Malformed;
    }
    if remainder.contains('/') {
        return NetworkOutcome::Path;
    }
    match remainder {
        "" | "^" => NetworkOutcome::Domain {
            host: domain_part.to_ascii_lowercase(),
            modifier: None,
        },
        _ => {
            let Some(modifier_str) = remainder
                .strip_prefix('^')
                .unwrap_or(remainder)
                .strip_prefix('$')
            else {
                return NetworkOutcome::Malformed;
            };
            match ModifierKind::parse(modifier_str) {
                Some(kind) => NetworkOutcome::Domain {
                    host: domain_part.to_ascii_lowercase(),
                    modifier: Some(kind),
                },
                None => NetworkOutcome::ModifierDiscarded,
            }
        }
    }
}

/// 1行の分類結果。
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineOutcome {
    Blank,
    Comment,
    Cosmetic,
    Wildcard,
    Exception(NetworkOutcome),
    Rule(NetworkOutcome),
}

/// EasyList の1行を分類する。判定順序は「意味が確定しやすいもの」から
/// 先に見る：空行・comment → 要素隠し → wildcard/否定 → 例外 → network rule。
fn classify_line(raw: &str) -> LineOutcome {
    let line = raw.trim();
    if line.is_empty() {
        return LineOutcome::Blank;
    }
    if line.starts_with('!') {
        return LineOutcome::Comment;
    }
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") {
        return LineOutcome::Cosmetic;
    }
    if line.contains('*') || line.contains('~') {
        return LineOutcome::Wildcard;
    }
    match line.strip_prefix("@@") {
        Some(rest) => LineOutcome::Exception(classify_network_rule(rest)),
        None => LineOutcome::Rule(classify_network_rule(line)),
    }
}

/// `$` 修飾子つきで採用した件数の内訳。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ModifierCounts {
    pub third_party: u32,
    pub three_p: u32,
    pub all: u32,
    pub document: u32,
}

impl ModifierCounts {
    fn record(&mut self, kind: ModifierKind) {
        match kind {
            ModifierKind::ThirdParty => self.third_party += 1,
            ModifierKind::ThreeP => self.three_p += 1,
            ModifierKind::All => self.all += 1,
            ModifierKind::Document => self.document += 1,
        }
    }

    fn total(&self) -> u32 {
        self.third_party + self.three_p + self.all + self.document
    }
}

/// 種別ごとの件数。行数は入力の生行数を数え、`domains` / `exceptions` の
/// 件数（重複除去後）とは単位が違う。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub total_lines: u32,
    pub blank: u32,
    pub comment: u32,
    pub cosmetic: u32,
    pub wildcard: u32,
    /// `@@` で始まる行の総数（中身が読めたかどうかを問わない）。
    pub exception_total: u32,
    /// `@@` のうち、domain を抽出できて `# except:` として書き残した件数。
    pub exception_recorded: u32,
    pub domain_plain: u32,
    pub domain_modifier: ModifierCounts,
    pub modifier_discarded: u32,
    pub path: u32,
    pub other: u32,
    /// サフィックス照合の衝突により、採用 domain から落とした件数
    /// （`domains` の重複除去後の件数が単位。行数ではない）。
    pub dropped_by_exception: u32,
}

/// 変換の結果。`domains` と `exceptions` は重複を除いて sort 済み。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Conversion {
    pub domains: Vec<String>,
    pub exceptions: Vec<String>,
    pub stats: Stats,
}

/// `exceptions` の各 domain 自身と、その祖先 domain（`src/blocklist.rs` の
/// `matches` が辿るのと同じ経路）をすべて集めた集合。採用 domain がこの集合に
/// 入っていれば、それを残すと当該 exception がサフィックス一致で当たって
/// しまう（「@@ の例外」の判断）。
fn covering_ancestors(exceptions: &BTreeSet<String>) -> HashSet<String> {
    let mut covering = HashSet::new();
    for exception in exceptions {
        covering.insert(exception.clone());
        let mut rest = exception.as_str();
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            covering.insert(rest.to_string());
        }
    }
    covering
}

/// EasyList 形式の `content` を blocklist 形式へ変換する。
///
/// **`@@` の例外の扱い**：`example.com` を採用し、
/// `@@||sub.example.com^` が在る場合、`sub.example.com` を出力に含めなくても
/// `src/blocklist.rs:87-93` のサフィックス一致で `example.com` に当たって
/// しまう。この module は、採用 domain が exception 自身か exception の
/// 祖先であるとき、その採用 domain を出力から落とす。理由は2つ。
/// 1つは、blocklist 形式が「domain と、そのサブドメイン全部」しか表現できず、
/// 「domain を落とすが、この1つのサブドメインだけは除く」を表現する型が
/// 無いこと。もう1つは、`docs/design.md`「制約」の「判定できない flow は
/// 通す」「遮断できないときは素通しに倒す」という既定方針で、EasyList の
/// 作者が明示的に許可した通信を誤って遮断し続けるより、広告1件を見逃す方を
/// 選ぶこと。落とした domain は集計にだけ残し（`Stats::dropped_by_exception`）、
/// 出力へは書かない。
pub fn convert(content: &str) -> Conversion {
    let mut stats = Stats::default();
    let mut accepted: BTreeSet<String> = BTreeSet::new();
    let mut exceptions: BTreeSet<String> = BTreeSet::new();

    for line in content.lines() {
        stats.total_lines += 1;
        match classify_line(line) {
            LineOutcome::Blank => stats.blank += 1,
            LineOutcome::Comment => stats.comment += 1,
            LineOutcome::Cosmetic => stats.cosmetic += 1,
            LineOutcome::Wildcard => stats.wildcard += 1,
            LineOutcome::Exception(outcome) => {
                stats.exception_total += 1;
                if let NetworkOutcome::Domain { host, .. } = outcome {
                    exceptions.insert(host);
                    stats.exception_recorded += 1;
                }
            }
            LineOutcome::Rule(outcome) => match outcome {
                NetworkOutcome::Domain { host, modifier } => {
                    match modifier {
                        None => stats.domain_plain += 1,
                        Some(kind) => stats.domain_modifier.record(kind),
                    }
                    accepted.insert(host);
                }
                NetworkOutcome::ModifierDiscarded => stats.modifier_discarded += 1,
                NetworkOutcome::Path => stats.path += 1,
                NetworkOutcome::NotNetworkRule | NetworkOutcome::Malformed => stats.other += 1,
            },
        }
    }

    let covering = covering_ancestors(&exceptions);
    let before = accepted.len();
    accepted.retain(|host| !covering.contains(host));
    stats.dropped_by_exception = (before - accepted.len()) as u32;

    let locale = crate::i18n::locale();
    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::filterlist_converted(
            locale,
            stats.total_lines,
            accepted.len(),
            exceptions.len(),
            stats.domain_plain + stats.domain_modifier.total(),
            stats.domain_plain,
            stats.domain_modifier.total(),
            stats.dropped_by_exception,
        )
    );
    if stats.other > 0 {
        eprintln!(
            "packetdeath: [warn] {}",
            crate::i18n::filterlist_unparsable_lines(locale, stats.other)
        );
    }

    Conversion {
        domains: accepted.into_iter().collect(),
        exceptions: exceptions.into_iter().collect(),
        stats,
    }
}

/// `convert` の結果を、`src/blocklist.rs` が読む形式へ整形する。冒頭に
/// 変換の要約と `# except:` 行を `#` コメントとして置き、その後に
/// sort 済み・重複無しの domain を1行1つ並べる。
/// `generated_at` は呼び出し側（`main.rs`）が RFC 3339 で整形済みの文字列を渡す
/// （この module は `time` crate に依存しない）。
pub fn render(conversion: &Conversion, input_name: &str, generated_at: &str) -> String {
    let s = &conversion.stats;
    let locale = crate::i18n::locale();
    let mut out = String::new();
    out.push_str(&crate::i18n::filterlist_header_comment(locale));
    out.push_str(&format!(
        "# input={input_name} lines={} generated_at={generated_at}\n",
        s.total_lines
    ));
    out.push_str(&crate::i18n::filterlist_accepted_comment(
        locale,
        conversion.domains.len(),
        s.domain_plain,
        s.domain_modifier.third_party,
        s.domain_modifier.three_p,
        s.domain_modifier.all,
        s.domain_modifier.document,
    ));
    out.push_str(&crate::i18n::filterlist_dropped_comment(
        locale,
        s.comment,
        s.blank,
        s.cosmetic,
        s.wildcard,
        s.exception_total,
        s.exception_recorded,
        s.path,
        s.modifier_discarded,
        s.other,
        s.dropped_by_exception,
    ));
    for exception in &conversion.exceptions {
        out.push_str("# except: ");
        out.push_str(exception);
        out.push('\n');
    }
    for domain in &conversion.domains {
        out.push_str(domain);
        out.push('\n');
    }
    out
}

/// allowlist 変換の入力形式。[`detect_allow_source`] が判定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowSource {
    /// Microsoft 公式 API の JSON（`[{"urls": [...]}, ...]`）。
    MicrosoftJson,
    /// Adblock Plus 形式の allow rule（`@@||example.com^`。hagezi 等）。
    Adblock,
    /// 1行1 domain の平文（`#` コメント可。anudeepND 等）。
    Plain,
}

/// `content` の形式を判定する。JSON として parse できれば `MicrosoftJson`。
/// そうでなく `@@||` で始まる行が1つでもあれば `Adblock`。どちらでもなければ
/// `Plain`。
///
/// **`[Adblock Plus]` ヘッダーを JSON と誤判定しない。**「先頭が `[`」だけで
/// 判定すると hagezi のヘッダー行に誤反応するため、実際に JSON として
/// parse できるかで判定する。
pub fn detect_allow_source(content: &str) -> AllowSource {
    if serde_json::from_str::<serde_json::Value>(content).is_ok() {
        return AllowSource::MicrosoftJson;
    }
    if content
        .lines()
        .any(|line| line.trim_start().starts_with("@@||"))
    {
        return AllowSource::Adblock;
    }
    AllowSource::Plain
}

/// allowlist 変換の件数。形式によらず同じ形で報告する。
/// **`total_candidates` の単位は形式により異なる**（`Adblock` / `Plain` は
/// 入力の生行数、`MicrosoftJson` は `urls` 配列の総要素数）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AllowStats {
    pub total_candidates: u32,
    /// 採用した domain 数（重複除去後）。
    pub accepted: u32,
    /// `*` が先頭以外に在る、または path/修飾子付きで捨てた件数。
    pub discarded: u32,
}

/// allowlist 変換の結果。`domains` は重複を除いて sort 済み。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowConversion {
    pub source: AllowSource,
    pub domains: Vec<String>,
    pub stats: AllowStats,
}

/// `*.example.com` の先頭ワイルドカードだけを剥がして採用する。`*` が
/// 先頭以外（`foo.*.example.com`）や、`*.` の形でない先頭（`*cdn.example.com`）
/// に在るものは `None`（捨てる）。
fn normalize_wildcard_host(url: &str) -> Option<String> {
    let host = url.strip_prefix("*.").unwrap_or(url);
    if host.contains('*') {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Microsoft 公式 API の JSON（`[{"urls": [...]}, ...]`）の1要素。
/// 判定に使うのは `urls` だけなので、他の field（`id` / `serviceArea` /
/// `ips` 等）は読まない。`#[serde(deny_unknown_fields)]` は付けない ──
/// Microsoft 側が将来 field を足しても、この reader を壊さないため。
#[derive(Debug, Deserialize)]
struct MsEndpoint {
    #[serde(default)]
    urls: Vec<String>,
}

fn convert_ms_json_allowlist(content: &str) -> AllowConversion {
    let mut stats = AllowStats::default();
    let mut domains: BTreeSet<String> = BTreeSet::new();
    match serde_json::from_str::<Vec<MsEndpoint>>(content) {
        Ok(endpoints) => {
            for endpoint in &endpoints {
                for url in &endpoint.urls {
                    stats.total_candidates += 1;
                    match normalize_wildcard_host(url) {
                        Some(host) => {
                            domains.insert(host);
                        }
                        None => stats.discarded += 1,
                    }
                }
            }
        }
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                crate::i18n::microsoft_json_parse_failed(crate::i18n::locale(), e)
            );
        }
    }
    stats.accepted = domains.len() as u32;
    AllowConversion {
        source: AllowSource::MicrosoftJson,
        domains: domains.into_iter().collect(),
        stats,
    }
}

/// `@@||example.com^`（Adblock Plus の allow rule）から domain を採る。
/// **意味が `convert`（EasyList → blocklist）と逆**：ここでは `@@` の中身
/// こそが採用対象である（allowlist は「当たっても通す」なので、hagezi の
/// 「配信を止めない」対象＝ `@@` の中身をそのまま採る）。
fn convert_adblock_allowlist(content: &str) -> AllowConversion {
    let mut stats = AllowStats::default();
    let mut domains: BTreeSet<String> = BTreeSet::new();
    for line in content.lines() {
        stats.total_candidates += 1;
        let Some(rest) = line.trim().strip_prefix("@@||") else {
            continue;
        };
        if rest.contains('*') {
            stats.discarded += 1;
            continue;
        }
        let (domain_part, remainder) = take_domain_token(rest);
        if domain_part.is_empty() || !matches!(remainder, "" | "^") {
            stats.discarded += 1;
            continue;
        }
        domains.insert(domain_part.to_ascii_lowercase());
    }
    stats.accepted = domains.len() as u32;
    AllowConversion {
        source: AllowSource::Adblock,
        domains: domains.into_iter().collect(),
        stats,
    }
}

/// 1行1 domain の平文（`#` コメント可。`Allowlist::parse` と同じ形式）。
fn convert_plain_allowlist(content: &str) -> AllowConversion {
    let mut stats = AllowStats::default();
    let mut domains: BTreeSet<String> = BTreeSet::new();
    for line in content.lines() {
        stats.total_candidates += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        domains.insert(trimmed.to_ascii_lowercase());
    }
    stats.accepted = domains.len() as u32;
    AllowConversion {
        source: AllowSource::Plain,
        domains: domains.into_iter().collect(),
        stats,
    }
}

/// `content` の形式を [`detect_allow_source`] で判定し、対応する変換へ渡す。
/// `packetdeath allowlist-convert --in <path> --out <path>` の実体。
pub fn convert_allowlist(content: &str) -> AllowConversion {
    match detect_allow_source(content) {
        AllowSource::MicrosoftJson => convert_ms_json_allowlist(content),
        AllowSource::Adblock => convert_adblock_allowlist(content),
        AllowSource::Plain => convert_plain_allowlist(content),
    }
}

/// [`convert_allowlist`] の結果を `src/allowlist.rs` が読む形式へ整形する。
/// `render`（blocklist 用）と同じく、冒頭に変換の要約を `#` コメントで置く。
pub fn render_allowlist(
    conversion: &AllowConversion,
    input_name: &str,
    generated_at: &str,
) -> String {
    let source_str = match conversion.source {
        AllowSource::MicrosoftJson => "microsoft-json",
        AllowSource::Adblock => "adblock",
        AllowSource::Plain => "plain",
    };
    let locale = crate::i18n::locale();
    let mut out = String::new();
    out.push_str(&crate::i18n::allowlist_convert_header_comment(locale));
    out.push_str(&format!(
        "# input={input_name} source={source_str} generated_at={generated_at}\n"
    ));
    out.push_str(&crate::i18n::allowlist_convert_accepted_comment(
        locale,
        conversion.stats.accepted as usize,
        conversion.stats.discarded,
    ));
    for domain in &conversion.domains {
        out.push_str(domain);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_produces_zero_of_everything() {
        let conversion = convert("");
        assert_eq!(conversion.stats.total_lines, 0);
        assert!(conversion.domains.is_empty());
        assert!(conversion.exceptions.is_empty());
    }

    #[test]
    fn blank_and_comment_lines_are_discarded() {
        // テスト項目6：`^!` と空行を捨てる。
        let conversion = convert("\n! Title: test\n\n");
        assert_eq!(conversion.stats.blank, 2);
        assert_eq!(conversion.stats.comment, 1);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn plain_domain_with_caret_is_accepted() {
        // テスト項目1。
        let conversion = convert("||example.com^\n");
        assert_eq!(conversion.domains, vec!["example.com".to_string()]);
        assert_eq!(conversion.stats.domain_plain, 1);
    }

    #[test]
    fn plain_domain_without_caret_is_accepted() {
        // テスト項目1：`||example.com` も採る。
        let conversion = convert("||example.com\n");
        assert_eq!(conversion.domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn domain_is_lowercased() {
        let conversion = convert("||EXAMPLE.COM^\n");
        assert_eq!(conversion.domains, vec!["example.com".to_string()]);
    }

    #[test]
    fn cosmetic_lines_are_discarded() {
        // テスト項目3：`##` `#@#` `#?#` `#$#` を含む行を捨てる。
        let conversion = convert(
            "example.com##.ad-banner\nexample.com#@#.ad\nexample.com#?#.ad\nexample.com#$#.ad\n",
        );
        assert_eq!(conversion.stats.cosmetic, 4);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn path_rules_are_discarded() {
        // テスト項目5。
        let conversion = convert("||example.com/ads/banner.gif\n");
        assert_eq!(conversion.stats.path, 1);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn wildcard_and_negation_lines_are_discarded() {
        // テスト項目7。
        let conversion = convert("||*.example.com^\n||example.com^$~third-party\n");
        assert_eq!(conversion.stats.wildcard, 2);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn qualifying_modifiers_are_accepted_as_domain() {
        // テスト項目4：third-party / 3p / all / document だけ採る。
        let conversion = convert(concat!(
            "||a.example^$third-party\n",
            "||b.example^$3p\n",
            "||c.example^$all\n",
            "||d.example^$document\n",
        ));
        assert_eq!(
            conversion.domains,
            vec![
                "a.example".to_string(),
                "b.example".to_string(),
                "c.example".to_string(),
                "d.example".to_string(),
            ]
        );
        let m = conversion.stats.domain_modifier;
        assert_eq!((m.third_party, m.three_p, m.all, m.document), (1, 1, 1, 1));
    }

    #[test]
    fn non_qualifying_modifiers_are_discarded() {
        // テスト項目4の裏：popup 等は採らない。複合修飾子（カンマ区切り）も
        // 「修飾子が third-party/3p/all/document だけ」に当たらないので捨てる。
        let conversion = convert(concat!(
            "||example.com^$popup\n",
            "||other.example^$third-party,image\n",
        ));
        assert_eq!(conversion.stats.modifier_discarded, 2);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn exception_is_not_emitted_as_domain_but_recorded_as_comment() {
        // テスト項目2前半。
        let conversion = convert("@@||example.com^\n");
        assert!(conversion.domains.is_empty());
        assert_eq!(conversion.exceptions, vec!["example.com".to_string()]);
        assert_eq!(conversion.stats.exception_total, 1);
        assert_eq!(conversion.stats.exception_recorded, 1);
    }

    #[test]
    fn exception_for_subdomain_drops_the_blocked_parent_domain() {
        // `sub.example.com` を残しても
        // `example.com` の suffix 一致で当たるので、`example.com` ごと落とす。
        let conversion = convert("||example.com^\n@@||sub.example.com^\n");
        assert!(conversion.domains.is_empty());
        assert_eq!(conversion.exceptions, vec!["sub.example.com".to_string()]);
        assert_eq!(conversion.stats.dropped_by_exception, 1);
    }

    #[test]
    fn exception_for_exact_domain_drops_the_same_blocked_domain() {
        let conversion = convert("||example.com^\n@@||example.com^\n");
        assert!(conversion.domains.is_empty());
        assert_eq!(conversion.stats.dropped_by_exception, 1);
    }

    #[test]
    fn unrelated_exception_does_not_drop_unrelated_domain() {
        let conversion = convert("||example.com^\n@@||other.example^\n");
        assert_eq!(conversion.domains, vec!["example.com".to_string()]);
        assert_eq!(conversion.stats.dropped_by_exception, 0);
    }

    #[test]
    fn output_is_deduplicated_and_sorted() {
        // テスト項目8。
        let conversion = convert("||b.example^\n||a.example^\n||a.example^\n");
        assert_eq!(
            conversion.domains,
            vec!["a.example".to_string(), "b.example".to_string()]
        );
    }

    #[test]
    fn line_not_starting_with_double_pipe_is_other() {
        let conversion = convert(".pk/ads/$~xmlhttprequest\n");
        // `~` を含むので wildcard 側で先に捨てる。
        assert_eq!(conversion.stats.wildcard, 1);
    }

    #[test]
    fn line_without_pipe_and_without_wildcard_is_other() {
        let conversion = convert("/a/display.php\n");
        assert_eq!(conversion.stats.other, 1);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn malformed_double_pipe_without_domain_is_other() {
        let conversion = convert("||^\n");
        assert_eq!(conversion.stats.other, 1);
    }

    #[test]
    fn stats_categories_sum_to_total_lines() {
        let content = concat!(
            "! comment\n",
            "\n",
            "example.com##.ad\n",
            "||*.example.com^\n",
            "@@||example.com^\n",
            "||a.example^\n",
            "||b.example^$third-party\n",
            "||c.example^$popup\n",
            "||d.example/path\n",
            "/other/path\n",
        );
        let conversion = convert(content);
        let s = conversion.stats;
        let accounted = s.blank
            + s.comment
            + s.cosmetic
            + s.wildcard
            + s.exception_total
            + s.domain_plain
            + s.domain_modifier.total()
            + s.modifier_discarded
            + s.path
            + s.other;
        assert_eq!(accounted, s.total_lines);
    }

    #[test]
    fn render_includes_summary_except_and_sorted_domains() {
        // domain 名は「# except: 」行の文字列とは互いに部分文字列に
        // ならないものを選ぶ（find による位置比較が誤って一致しないように）。
        let conversion = convert("||zeta.example^\n||alpha.example^\n@@||notthesame.example^\n");
        let rendered = render(&conversion, "in.txt", "2026-09-11T00:00:00Z");
        assert!(rendered.contains("# input=in.txt"));
        assert!(rendered.contains("# except: notthesame.example"));
        let alpha_pos = rendered.find("alpha.example");
        let zeta_pos = rendered.find("zeta.example");
        assert!(alpha_pos.is_some() && zeta_pos.is_some());
        assert!(alpha_pos < zeta_pos);
    }

    #[test]
    fn detect_allow_source_recognizes_ms_json() {
        let content = r#"[{"id":1,"urls":["outlook.office.com"]}]"#;
        assert_eq!(detect_allow_source(content), AllowSource::MicrosoftJson);
    }

    #[test]
    fn detect_allow_source_does_not_mistake_adblock_plus_header_for_json() {
        // hagezi の1行目 `[Adblock Plus]` は `[` で始まるが JSON ではない。
        let content = "[Adblock Plus]\n! Title: test\n@@||example.com^\n";
        assert_eq!(detect_allow_source(content), AllowSource::Adblock);
    }

    #[test]
    fn detect_allow_source_recognizes_plain() {
        let content = "1drv.com\nexample.com\n";
        assert_eq!(detect_allow_source(content), AllowSource::Plain);
    }

    #[test]
    fn convert_ms_json_allowlist_strips_leading_wildcard() {
        let content = r#"[{"urls":["*.auth.microsoft.com","outlook.office.com"]}]"#;
        let conversion = convert_allowlist(content);
        assert_eq!(conversion.source, AllowSource::MicrosoftJson);
        assert_eq!(
            conversion.domains,
            vec![
                "auth.microsoft.com".to_string(),
                "outlook.office.com".to_string()
            ]
        );
        assert_eq!(conversion.stats.discarded, 0);
    }

    #[test]
    fn convert_ms_json_allowlist_drops_wildcard_not_at_leading_position() {
        // `*` が先頭以外（`foo.*.example.com`）や、`*.` の形でない
        // 先頭（`*cdn.example.com`）は捨てる。
        let content =
            r#"[{"urls":["autodiscover.*.onmicrosoft.com","*cdn.onenote.net","ok.example.com"]}]"#;
        let conversion = convert_allowlist(content);
        assert_eq!(conversion.domains, vec!["ok.example.com".to_string()]);
        assert_eq!(conversion.stats.discarded, 2);
    }

    #[test]
    fn convert_ms_json_allowlist_reports_error_on_malformed_json_without_panicking() {
        // JSON としては有効（`serde_json::Value` として parse できる）だが、
        // 配列でも `urls` field でもない構造。panic せず空の domains を返す。
        let conversion = convert_allowlist(r#"{"not":"an array"}"#);
        assert_eq!(conversion.source, AllowSource::MicrosoftJson);
        assert!(conversion.domains.is_empty());
    }

    #[test]
    fn convert_adblock_allowlist_extracts_domain_from_exception_rule() {
        let content = "! comment\n@@||example.org^\n";
        let conversion = convert_allowlist(content);
        assert_eq!(conversion.source, AllowSource::Adblock);
        assert_eq!(conversion.domains, vec!["example.org".to_string()]);
    }

    #[test]
    fn convert_adblock_allowlist_drops_wildcard_rule() {
        // hagezi 実データにある形（`@@||*-go.kelkoogroup.net^`）。
        let content = "@@||*-go.kelkoogroup.net^\n@@||ok.example^\n";
        let conversion = convert_allowlist(content);
        assert_eq!(conversion.domains, vec!["ok.example".to_string()]);
        assert_eq!(conversion.stats.discarded, 1);
    }

    #[test]
    fn convert_adblock_allowlist_ignores_non_exception_lines() {
        let content = "[Adblock Plus]\n! Title\n||blocked.example^\nplain-line\n@@||ok.example^\n";
        let conversion = convert_allowlist(content);
        assert_eq!(conversion.domains, vec!["ok.example".to_string()]);
    }

    #[test]
    fn convert_plain_allowlist_ignores_comment_and_blank_lines() {
        let content = "# comment\n\n1drv.com\nOK.Example\n";
        let conversion = convert_allowlist(content);
        assert_eq!(conversion.source, AllowSource::Plain);
        assert_eq!(
            conversion.domains,
            vec!["1drv.com".to_string(), "ok.example".to_string()]
        );
    }

    #[test]
    fn render_allowlist_includes_source_and_domains() {
        let conversion = convert_allowlist("1drv.com\n");
        let rendered = render_allowlist(&conversion, "in.txt", "2026-09-11T00:00:00Z");
        assert!(rendered.contains("source=plain"));
        assert!(rendered.contains("1drv.com"));
    }
}
