//! Guards the README reference tables against drifting from the command line.
//!
//! What it protects: every `--option` and every command word in the usage
//! lines of `src/i18n.rs` has a row in the reference section of both READMEs.
//! A row counts when its first table cell holds the name in backticks, so a
//! mention inside another option's description does not satisfy it.
//!
//! Source of truth: the two usage lines in `src/i18n.rs` (the `Locale::Ja` and
//! `Locale::En` arms of `usage_banner`). They are found by their opening text,
//! not by line number. The reference sections are `## command と option の一覧`
//! in `README.ja.md` and `## Commands and options` in `README.md`; a section
//! runs up to the next `## ` heading, so its `###` subsections belong to it.
//!
//! When a test here fails:
//! - A name is listed as missing: add a table row for it in the named README
//!   (first cell `` `--name` `` or `` `command` ``), in that language's section.
//! - The ja and en option sets differ: fix the usage line that lacks the option.
//! - Fewer than the minimum options or commands were read, or a section was not
//!   found: the scanner or a heading no longer matches the files; fix the
//!   constants below, never lower a minimum to make a count pass.
//!
//! Tests return `Result` and use `?`; no unwrap/expect.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

type TestResult = Result<(), Box<dyn Error>>;

const I18N: &str = "src/i18n.rs";
const JA_README: &str = "README.ja.md";
const EN_README: &str = "README.md";
const JA_HEADING: &str = "## command と option の一覧";
const EN_HEADING: &str = "## Commands and options";
const JA_USAGE_START: &str = "\"使い方: packetdeath";
const EN_USAGE_START: &str = "\"usage: packetdeath";
/// The usage lines carry 33 options and 10 commands; a scan that reads far
/// fewer has stopped matching the file, not found a smaller CLI.
const MIN_OPTIONS: usize = 30;
const MIN_COMMANDS: usize = 10;

fn read_repo_file(relative: &str) -> Result<String, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .map_err(|error| Box::<dyn Error>::from(format!("cannot read {}: {error}", path.display())))
}

/// The one source line of `i18n` that starts a usage string.
fn usage_line(i18n: &str, start: &str) -> Result<String, Box<dyn Error>> {
    let Some(line) = i18n.lines().find(|line| line.contains(start)) else {
        return Err(format!("{I18N} has no usage line containing {start}").into());
    };
    Ok(line.to_owned())
}

/// The ja and en usage lines, in that order.
fn usage_lines() -> Result<(String, String), Box<dyn Error>> {
    let i18n = read_repo_file(I18N)?;
    Ok((
        usage_line(&i18n, JA_USAGE_START)?,
        usage_line(&i18n, EN_USAGE_START)?,
    ))
}

/// Whether `byte` can be part of an option name or of a word that holds one.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

/// Every `--name` in `text`: lowercase letters, digits and inner hyphens,
/// starting with a letter and not glued to a preceding word (`a--b` is not one).
fn options_in(text: &str) -> BTreeSet<&str> {
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    for (at, _) in text.match_indices("--") {
        if at > 0 && is_name_byte(bytes[at - 1]) {
            continue;
        }
        let rest = &text[at + 2..];
        let run = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            .count();
        let name = rest[..run].trim_end_matches('-');
        if name.starts_with(|first: char| first.is_ascii_lowercase()) {
            found.insert(&text[at..at + 2 + name.len()]);
        }
    }
    found
}

/// Every command word: the lowercase word after each `packetdeath ` in a usage line.
fn commands_in(usage: &str) -> BTreeSet<&str> {
    usage
        .match_indices("packetdeath ")
        .filter_map(|(at, spelled)| {
            let rest = &usage[at + spelled.len()..];
            let run = rest
                .bytes()
                .take_while(|byte| byte.is_ascii_lowercase() || *byte == b'-')
                .count();
            rest.starts_with(|first: char| first.is_ascii_lowercase())
                .then(|| &rest[..run])
        })
        .collect()
}

/// Options named by either usage line.
fn usage_options() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let (ja, en) = usage_lines()?;
    Ok(options_in(&ja)
        .into_iter()
        .chain(options_in(&en))
        .map(str::to_owned)
        .collect())
}

/// Commands named by either usage line.
fn usage_commands() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let (ja, en) = usage_lines()?;
    Ok(commands_in(&ja)
        .into_iter()
        .chain(commands_in(&en))
        .map(str::to_owned)
        .collect())
}

/// The text under `heading` up to the next `## ` heading, `###` included.
fn section_of<'a>(readme: &'a str, heading: &str) -> Option<&'a str> {
    let marker = format!("\n{heading}\n");
    let body = &readme[readme.find(&marker)? + marker.len()..];
    match body.find("\n## ") {
        Some(end) => Some(&body[..end]),
        None => Some(body),
    }
}

fn load_section(file: &str, heading: &str) -> Result<String, Box<dyn Error>> {
    let readme = read_repo_file(file)?;
    match section_of(&readme, heading) {
        Some(section) => Ok(section.to_owned()),
        None => Err(format!("{file} has no section \"{heading}\"").into()),
    }
}

/// The first cell of every table row (a line starting with `|`).
fn first_cells(section: &str) -> Vec<&str> {
    section
        .lines()
        .filter_map(|line| line.strip_prefix('|'))
        .filter_map(|row| row.split('|').next())
        .collect()
}

/// The names that no table row of `section` holds, in backticks, in its first cell.
fn missing_names<'a>(section: &str, names: &'a BTreeSet<String>) -> Vec<&'a str> {
    let cells = first_cells(section);
    names
        .iter()
        .filter(|name| {
            let needle = format!("`{name}`");
            !cells.iter().any(|cell| cell.contains(&needle))
        })
        .map(String::as_str)
        .collect()
}

fn assert_all_documented(file: &str, heading: &str, names: &BTreeSet<String>) -> TestResult {
    let section = load_section(file, heading)?;
    let missing = missing_names(&section, names);
    assert!(
        missing.is_empty(),
        "{file} \"{heading}\" has no table row for {} name(s): {missing:?}",
        missing.len()
    );
    Ok(())
}

#[test]
fn usage_lines_yield_all_options() -> TestResult {
    let (ja, en) = usage_lines()?;
    let (ja, en) = (options_in(&ja), options_in(&en));
    assert!(
        ja.len() >= MIN_OPTIONS,
        "ja usage yields {} options: {ja:?}",
        ja.len()
    );
    assert!(
        en.len() >= MIN_OPTIONS,
        "en usage yields {} options: {en:?}",
        en.len()
    );
    assert_eq!(ja, en, "ja and en usage lines name different options");
    Ok(())
}

#[test]
fn every_option_is_in_the_ja_reference_table() -> TestResult {
    assert_all_documented(JA_README, JA_HEADING, &usage_options()?)
}

#[test]
fn every_option_is_in_the_en_reference_table() -> TestResult {
    assert_all_documented(EN_README, EN_HEADING, &usage_options()?)
}

#[test]
fn every_command_is_in_both_reference_sections() -> TestResult {
    let commands = usage_commands()?;
    assert!(
        commands.len() >= MIN_COMMANDS,
        "usage lines yield {} commands: {commands:?}",
        commands.len()
    );
    assert_all_documented(JA_README, JA_HEADING, &commands)?;
    assert_all_documented(EN_README, EN_HEADING, &commands)
}

const SAMPLE_TABLE: &str =
    "| Option | Value |\n|---|---|\n| `--queue` | number |\n| `--filter` | expression |\n";

fn names(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

/// Negative control: dropping one row makes the check name exactly that option.
#[test]
fn a_missing_option_is_reported() {
    let wanted = names(&["--queue", "--filter"]);
    assert!(missing_names(SAMPLE_TABLE, &wanted).is_empty());
    let without = SAMPLE_TABLE.replace("| `--filter` | expression |\n", "");
    assert_eq!(missing_names(&without, &wanted), ["--filter"]);
}

/// A name in another row's description, or outside the section, is not a row.
#[test]
fn a_mention_or_a_row_outside_the_section_does_not_count() {
    let wanted = names(&["--queue", "--filter"]);
    let mention = "| `--queue` | same as `--filter` |\n";
    assert_eq!(missing_names(mention, &wanted), ["--filter"]);

    let readme = "# T\n\n## A\n| `--x` | y |\n### sub\n| `--w` | y |\n\n## B\n| `--z` | y |\n";
    let Some(section) = section_of(readme, "## A") else {
        panic!("section A was not found");
    };
    assert_eq!(
        missing_names(section, &names(&["--x", "--w", "--z"])),
        ["--z"]
    );
    assert_eq!(section_of(readme, "## C"), None);
}

#[test]
fn the_scanner_reads_flags_only() {
    let text = "x [--a-b <1-3>]... (--c | --d) a--e\n---|---\n--- foo -- --F --g-";
    let found: Vec<&str> = options_in(text).into_iter().collect();
    assert_eq!(found, ["--a-b", "--c", "--d", "--g"]);
    let usage = "usage: packetdeath observe [--q]\n      packetdeath defense-report (--f)";
    let commands: Vec<&str> = commands_in(usage).into_iter().collect();
    assert_eq!(commands, ["defense-report", "observe"]);
}
