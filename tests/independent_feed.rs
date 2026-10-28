//! Independent check of `scripts/pd-malware-feed.sh`: PK-132 (the new outputs),
//! PK-143 (`--auth`) and the PK-94 regression. `docs/design.md` "段階10 能動防御"
//! 方針5 and "受入 ID" are the source of truth.
//!
//! No test reaches the network. The key tests put a recording `curl` first on
//! `PATH`; it appends one line per request (`<url> <1 if -K was given>`, the URL
//! read from the `url = "..."` config line on stdin when `-K -` is given) to
//! one record and its whole argv to another, and writes a placeholder body.
//! Requests to ThreatFox and URLhaus are counted from the first record, so "no
//! key means zero requests" is measured, not assumed, and the second record
//! shows the key text is never in argv.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

/// A key of the shape the script accepts: 48 hex digits.
const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
const TF_HOST: &str = "threatfox-api.abuse.ch";
const UH_HOST: &str = "urlhaus-api.abuse.ch";

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/pd-malware-feed.sh")
}

fn fresh_dir(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("feed-{name}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A `curl` that records its requests in `log` and its argv in `argv_log`, and
/// writes a placeholder body. With `-K -` the URL comes from the config line
/// on stdin, as in the real tool.
fn install_recording_curl(
    dir: &Path,
    log: &Path,
    argv_log: &Path,
) -> Result<PathBuf, Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let body = format!(
        "#!/bin/sh\nurl=; out=; k=0\n\
         printf '%s\\n' \"$*\" >> '{}'\n\
         while [ $# -gt 0 ]; do\n\
         case $1 in -o) out=$2; shift ;; \
         -K) k=1; [ \"$2\" = - ] && url=$(sed -n 's/^url = \"\\(.*\\)\"$/\\1/p'); shift ;; \
         --max-time) shift ;; -*) ;; *) url=$1 ;; esac\n\
         shift\ndone\n\
         printf '%s %s\\n' \"$url\" \"$k\" >> '{}'\n\
         printf 'x\\n' > \"$out\"\n",
        argv_log.display(),
        log.display()
    );
    let path = bin.join("curl");
    std::fs::write(&path, body)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(bin)
}

fn write_key(dir: &Path, mode: u32) -> Result<PathBuf, Box<dyn Error>> {
    let path = dir.join("auth.curl");
    std::fs::write(&path, format!("header = \"Auth-Key: {SECRET}\"\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    Ok(path)
}

/// What a run with the recording `curl` left behind.
struct Recorded {
    output: Output,
    /// One `<url> <1 if -K was given>` line per request.
    log: String,
    /// One line per `curl` call: its whole argv.
    argv: String,
}

fn run_with_fake_curl(dir: &Path, auth: Option<&Path>) -> Result<Recorded, Box<dyn Error>> {
    let log = dir.join("requests.log");
    let argv_log = dir.join("argv.log");
    std::fs::write(&log, "")?;
    std::fs::write(&argv_log, "")?;
    let bin = install_recording_curl(dir, &log, &argv_log)?;
    let out = dir.join("out");
    let mut command = Command::new("/bin/sh");
    command
        .arg(script())
        .args(["--out"])
        .arg(&out)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    if let Some(auth) = auth {
        command.arg("--auth").arg(auth);
    }
    let output = command.output()?;
    Ok(Recorded {
        output,
        log: std::fs::read_to_string(&log)?,
        argv: std::fs::read_to_string(&argv_log)?,
    })
}

fn requests_to(log: &str, host: &str) -> usize {
    log.lines().filter(|line| line.contains(host)).count()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// PK-143, no key file: zero requests to ThreatFox and URLhaus, no `-K` at all.
#[test]
fn without_a_key_file_threatfox_and_urlhaus_get_no_request() -> TestResult {
    let dir = fresh_dir("nokey")?;
    let absent = dir.join("absent.curl");
    for auth in [None, Some(absent.as_path())] {
        let Recorded { output, log, .. } = run_with_fake_curl(&dir, auth)?;
        assert_eq!(requests_to(&log, TF_HOST), 0, "{log}");
        assert_eq!(requests_to(&log, UH_HOST), 0, "{log}");
        assert!(!log.lines().any(|line| line.ends_with(" 1")), "{log}");
        // The control: keyless feeds were requested in the same run.
        assert_eq!(requests_to(&log, "feodotracker.abuse.ch"), 1, "{log}");
        assert_eq!(requests_to(&log, "sslbl.abuse.ch"), 2, "{log}");
        assert_eq!(requests_to(&log, "mozilla.com"), 1, "{log}");
        let stderr = stderr_of(&output);
        assert_eq!(stderr.matches("not requested").count(), 2, "{stderr}");
        assert_eq!(output.status.code(), Some(1), "{stderr}");
    }
    Ok(())
}

/// PK-143, key file 0600: each key feed is requested once, at its own path
/// with the key in it, through `-K -`; the keyless feeds get no `-K`; and the
/// key text is nowhere in any `curl` argv, in stdout or in stderr.
#[test]
fn a_0600_key_file_reaches_curl_on_stdin_and_never_in_argv() -> TestResult {
    let dir = fresh_dir("key0600")?;
    let key = write_key(&dir, 0o600)?;
    let Recorded { output, log, argv } = run_with_fake_curl(&dir, Some(&key))?;
    let tf = format!("https://{TF_HOST}/v2/files/exports/{SECRET}/recent.csv 1");
    let uh = format!("https://{UH_HOST}/v2/files/exports/{SECRET}/hostfile.txt 1");
    assert_eq!(log.lines().filter(|line| *line == tf).count(), 1, "{log}");
    assert_eq!(log.lines().filter(|line| *line == uh).count(), 1, "{log}");
    let with_key = log.lines().filter(|line| line.ends_with(" 1")).count();
    assert_eq!(with_key, 2, "{log}");
    assert!(log
        .lines()
        .filter(|l| l.contains("feodotracker"))
        .all(|l| l.ends_with(" 0")));
    // The control: the same record does hold the key (in the URL read from
    // stdin), so the absence from argv below is measured against a live record.
    assert!(log.contains(SECRET), "{log}");
    assert_eq!(argv.lines().count(), 6, "{argv}");
    assert_eq!(
        argv.lines().filter(|l| l.contains("-K -")).count(),
        2,
        "{argv}"
    );
    assert!(!argv.contains(SECRET), "{argv}");
    assert!(!argv.contains("Auth-Key"), "{argv}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!stderr_of(&output).contains(SECRET));
    assert_eq!(stderr_of(&output).matches("auth file").count(), 0);
    Ok(())
}

/// PK-143, key file 0644: the key is not used, one `[warn]` names the file.
#[test]
fn a_loose_key_file_is_not_used_and_is_warned_about_once() -> TestResult {
    let dir = fresh_dir("key0644")?;
    let key = write_key(&dir, 0o644)?;
    let Recorded { output, log, .. } = run_with_fake_curl(&dir, Some(&key))?;
    assert_eq!(requests_to(&log, TF_HOST), 0, "{log}");
    assert_eq!(requests_to(&log, UH_HOST), 0, "{log}");
    assert!(!log.lines().any(|line| line.ends_with(" 1")), "{log}");
    let stderr = stderr_of(&output);
    assert_eq!(stderr.matches("has mode 644").count(), 1, "{stderr}");
    assert!(!stderr.contains(SECRET));
    Ok(())
}

/// PK-143, a 0600 file whose content is not `header = "Auth-Key: <40-64 hex>"`:
/// no request to the two feeds, one `[warn]` naming the file, no key text.
#[test]
fn a_key_file_of_the_wrong_shape_is_not_used() -> TestResult {
    let dir = fresh_dir("keyshape")?;
    let key = dir.join("auth.curl");
    let too_long = format!("header = \"Auth-Key: {SECRET}0123456789abcdef0\"\n");
    let two_lines = format!("header = \"Auth-Key: {SECRET}\"\nheader = \"Auth-Key: {SECRET}\"\n");
    let cases = [
        ("header = \"Auth-Key: abcdef\"\n", "not 40 to 64 hex digits"),
        (too_long.as_str(), "not 40 to 64 hex digits"),
        (
            "header = \"Auth-Key: not-a-hex-key\"\n",
            "no Auth-Key header line",
        ),
        (two_lines.as_str(), "no Auth-Key header line"),
        ("", "no Auth-Key header line"),
    ];
    for (content, reason) in cases {
        std::fs::write(&key, content)?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
        let Recorded { output, log, .. } = run_with_fake_curl(&dir, Some(&key))?;
        assert_eq!(requests_to(&log, TF_HOST), 0, "{content:?} {log}");
        assert_eq!(requests_to(&log, UH_HOST), 0, "{content:?} {log}");
        let stderr = stderr_of(&output);
        assert_eq!(stderr.matches(reason).count(), 1, "{content:?} {stderr}");
        assert!(!stderr.contains(SECRET), "{stderr}");
    }
    Ok(())
}

/// The two ends of the accepted key length are used; one digit outside is not.
#[test]
fn the_key_length_bounds_are_40_and_64_digits() -> TestResult {
    let dir = fresh_dir("keybounds")?;
    let key = dir.join("auth.curl");
    for (digits, used) in [(39, 0), (40, 1), (64, 1), (65, 0)] {
        let text = "a1".repeat(digits).chars().take(digits).collect::<String>();
        std::fs::write(&key, format!("header = \"Auth-Key: {text}\"\n"))?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
        let Recorded { log, .. } = run_with_fake_curl(&dir, Some(&key))?;
        assert_eq!(requests_to(&log, TF_HOST), used, "{digits} digits: {log}");
        assert_eq!(requests_to(&log, UH_HOST), used, "{digits} digits: {log}");
    }
    Ok(())
}

/// A body that is not the feed (an error page served with status 200) counts
/// as not fetched: the run fails and the previous list is byte-identical.
#[test]
fn a_malformed_body_keeps_the_previous_list() -> TestResult {
    let dir = fresh_dir("malformed")?;
    let key = write_key(&dir, 0o600)?;
    let out = dir.join("out");
    std::fs::create_dir_all(&out)?;
    let previous = "# previous\nkept.example.com\n";
    std::fs::write(out.join("malware-domains.txt"), previous)?;
    let Recorded { output, log, .. } = run_with_fake_curl(&dir, Some(&key))?;
    assert_eq!(requests_to(&log, TF_HOST), 1, "{log}");
    assert_eq!(requests_to(&log, UH_HOST), 1, "{log}");
    let stderr = stderr_of(&output);
    assert_eq!(
        stderr.matches("body has no usable rows").count(),
        2,
        "{stderr}"
    );
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(out.join("malware-domains.txt"))?,
        previous
    );
    Ok(())
}

fn write_fixtures(from: &Path) -> TestResult {
    std::fs::create_dir_all(from)?;
    std::fs::write(
        from.join("threatfox.csv"),
        "# comment\n\"1\", \"2026-10-22 00:00:00\", \"bad.example.com\", \"domain\", \"x\"\n",
    )?;
    std::fs::write(
        from.join("urlhaus-hostfile.txt"),
        "# c\n127.0.0.1 evil.example.net\n",
    )?;
    std::fs::write(
        from.join("feodo-ipblocklist.txt"),
        "# c\n198.51.100.7\n10.0.0.1\n",
    )?;
    std::fs::write(
        from.join("onecrl.json"),
        r#"{"changes":[
        {"enabled":true,"subject":"AA==","pubKeyHash":"6+1kdcLC2A/LGZ8/6N1uazzmC3frFdTkLD3sDG9bUQU="},
        {"enabled":true,"issuerName":"MDwx","serialNumber":"AIAJ"},
        {"enabled":false,"pubKeyHash":"AAAA"}]}"#,
    )?;
    std::fs::write(
        from.join("sslblacklist.csv"),
        "# Listingdate,SHA1,Listingreason\n2026-10-21 15:55:24,e4c69c59c688b6b22688718fd601e7a3bc6e2c8a,x\n",
    )?;
    std::fs::write(from.join("sslipblacklist.txt"), "# DstIP\n198.51.100.99\n")?;
    Ok(())
}

fn run_from(dir: &Path, from: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new("/bin/sh")
        .arg(script())
        .arg("--out")
        .arg(dir.join("out"))
        .arg("--from")
        .arg(from)
        .args([
            "--min-domains",
            "1",
            "--min-ips",
            "1",
            "--min-distrust",
            "1",
        ])
        .args(["--min-sslbl-certs", "1"])
        .output()?)
}

fn entries(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

/// PK-132 and the PK-94 regression: every output is made from the fixtures, a
/// disabled OneCRL record is dropped, and the eMudhra count is logged.
#[test]
fn fixtures_make_the_five_outputs() -> TestResult {
    let dir = fresh_dir("from")?;
    let from = dir.join("raw-in");
    write_fixtures(&from)?;
    let output = run_from(&dir, &from)?;
    assert_eq!(output.status.code(), Some(0), "{}", stderr_of(&output));
    let out = dir.join("out");
    assert_eq!(entries(&out.join("malware-domains.txt"))?.len(), 2);
    assert_eq!(entries(&out.join("malware-ips.txt"))?, ["198.51.100.7"]);
    let distrust = entries(&out.join("distrust-onecrl.txt"))?;
    assert_eq!(distrust.len(), 2, "{distrust:?}");
    assert!(distrust.iter().any(|l| l.starts_with("spki-sha256 ")));
    assert!(distrust.iter().any(|l| l == "issuer-serial MDwx AIAJ"));
    assert_eq!(
        entries(&out.join("sslbl-certs.txt"))?,
        ["cert-sha1 e4c69c59c688b6b22688718fd601e7a3bc6e2c8a"]
    );
    assert_eq!(entries(&out.join("sslbl-ips.txt"))?, ["198.51.100.99"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(stdout.matches("onecrl emudhra=").count(), 1, "{stdout}");
    assert_eq!(
        stdout
            .matches("ThreatFox: fetched, 1 candidate rows")
            .count(),
        1,
        "{stdout}"
    );
    assert_eq!(
        stdout.matches("URLhaus: fetched, 1 candidate rows").count(),
        1,
        "{stdout}"
    );
    Ok(())
}

/// PK-132 and PK-94 negative control: a broken raw file leaves every previous
/// output byte-identical and the run fails.
#[test]
fn a_broken_raw_file_keeps_the_previous_outputs() -> TestResult {
    let dir = fresh_dir("broken")?;
    let from = dir.join("raw-in");
    write_fixtures(&from)?;
    assert_eq!(run_from(&dir, &from)?.status.code(), Some(0));
    let out = dir.join("out");
    // Entries only: a feed that is still good (Feodo) rewrites its file with a
    // new timestamp line and the same entries.
    let snapshot = |out: &Path| -> Result<Vec<Vec<String>>, Box<dyn Error>> {
        [
            "malware-domains.txt",
            "malware-ips.txt",
            "distrust-onecrl.txt",
            "sslbl-certs.txt",
            "sslbl-ips.txt",
        ]
        .iter()
        .map(|name| entries(&out.join(name)))
        .collect()
    };
    let before = snapshot(&out)?;
    std::fs::write(from.join("onecrl.json"), "<html>error</html>")?;
    std::fs::write(from.join("sslblacklist.csv"), "<html>error</html>")?;
    // An empty list is a valid answer, so an error page must not read as one.
    std::fs::write(from.join("sslipblacklist.txt"), "<html>error</html>\n")?;
    std::fs::write(from.join("threatfox.csv"), "garbage\n")?;
    std::fs::write(from.join("urlhaus-hostfile.txt"), "garbage\n")?;
    let output = run_from(&dir, &from)?;
    assert_eq!(output.status.code(), Some(1), "{}", stderr_of(&output));
    assert_eq!(snapshot(&out)?, before);
    Ok(())
}

/// PK-94: an error page of several words, served with status 200 in place of
/// one key feed while the other feed is good, is not a fetched feed: the run
/// fails, the warning names that feed, and no "fetched" line is logged for it.
#[test]
fn an_html_error_page_is_not_a_fetched_key_feed() -> TestResult {
    let page = "<html><body>Unauthorized access denied</body></html>\n";
    for (raw, label) in [
        ("threatfox.csv", "ThreatFox"),
        ("urlhaus-hostfile.txt", "URLhaus"),
    ] {
        let dir = fresh_dir(&format!("html-{label}"))?;
        let from = dir.join("raw-in");
        write_fixtures(&from)?;
        std::fs::write(from.join(raw), page)?;
        let output = run_from(&dir, &from)?;
        let stderr = stderr_of(&output);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let warning = format!("{label} body has no usable rows");
        assert_eq!(stderr.matches(&warning).count(), 1, "{label}: {stderr}");
        assert_eq!(output.status.code(), Some(1), "{label}: {stderr}");
        assert!(!stdout.contains(&format!("{label}: fetched")), "{stdout}");
        // The control: the feed that was left good is still counted.
        let other = if label == "ThreatFox" {
            "URLhaus"
        } else {
            "ThreatFox"
        };
        assert!(
            stdout.contains(&format!("{other}: fetched, 1 candidate rows")),
            "{stdout}"
        );
    }
    Ok(())
}

/// A key file the process cannot read (mode 0200) is not used: one `[warn]`,
/// no request to the two key feeds, and the keyless feeds are still fetched.
#[test]
fn an_unreadable_key_file_is_a_warning_and_keyless_feeds_still_run() -> TestResult {
    let dir = fresh_dir("keyunreadable")?;
    let key = write_key(&dir, 0o200)?;
    let Recorded { output, log, .. } = run_with_fake_curl(&dir, Some(&key))?;
    let stderr = stderr_of(&output);
    assert_eq!(stderr.matches("cannot be read").count(), 1, "{stderr}");
    assert!(!stderr.contains("can't read"), "{stderr}");
    assert_eq!(requests_to(&log, TF_HOST), 0, "{log}");
    assert_eq!(requests_to(&log, UH_HOST), 0, "{log}");
    assert_eq!(requests_to(&log, "feodotracker.abuse.ch"), 1, "{log}");
    assert_eq!(requests_to(&log, "sslbl.abuse.ch"), 2, "{log}");
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    Ok(())
}
