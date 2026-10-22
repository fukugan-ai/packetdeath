//! Independent check of `scripts/pd-malware-feed.sh`: PK-132 (the new outputs),
//! PK-143 (`--auth`) and the PK-94 regression. `docs/design.md` "段階10 能動防御"
//! 方針5 and "受入 ID" are the source of truth.
//!
//! No test reaches the network. The key tests put a recording `curl` first on
//! `PATH`; it appends one line per request (`<url> <1 if -K was given>`) and
//! writes a placeholder body. Requests to ThreatFox and URLhaus are counted
//! from that record, so "no key means zero requests" is measured, not assumed.

use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

const SECRET: &str = "SECRETKEYVALUE0123456789";

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

/// A `curl` that records its requests in `log` and writes a placeholder body.
fn install_recording_curl(dir: &Path, log: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin)?;
    let body = format!(
        "#!/bin/sh\nurl=; out=; k=0\n\
         while [ $# -gt 0 ]; do\n\
         case $1 in -o) out=$2; shift ;; -K) k=1; shift ;; --max-time) shift ;; -*) ;; *) url=$1 ;; esac\n\
         shift\ndone\n\
         printf '%s %s\\n' \"$url\" \"$k\" >> '{}'\n\
         printf 'x\\n' > \"$out\"\n",
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

fn run_with_fake_curl(dir: &Path, auth: Option<&Path>) -> Result<(Output, String), Box<dyn Error>> {
    let log = dir.join("requests.log");
    std::fs::write(&log, "")?;
    let bin = install_recording_curl(dir, &log)?;
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
    Ok((output, std::fs::read_to_string(&log)?))
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
        let (output, log) = run_with_fake_curl(&dir, auth)?;
        assert_eq!(requests_to(&log, "threatfox.abuse.ch"), 0, "{log}");
        assert_eq!(requests_to(&log, "urlhaus.abuse.ch"), 0, "{log}");
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

/// PK-143, key file 0600: both key feeds get `-K`, the keyless feeds do not,
/// and the key text is nowhere in the recorded argv.
#[test]
fn a_0600_key_file_goes_to_curl_with_dash_k_and_never_into_argv() -> TestResult {
    let dir = fresh_dir("key0600")?;
    let key = write_key(&dir, 0o600)?;
    let (output, log) = run_with_fake_curl(&dir, Some(&key))?;
    assert_eq!(requests_to(&log, "threatfox.abuse.ch"), 1, "{log}");
    assert_eq!(requests_to(&log, "urlhaus.abuse.ch"), 1, "{log}");
    let with_key: Vec<&str> = log.lines().filter(|line| line.ends_with(" 1")).collect();
    assert_eq!(with_key.len(), 2, "{log}");
    assert!(
        with_key.iter().all(|line| line.contains("abuse.ch/")),
        "{log}"
    );
    assert!(log
        .lines()
        .filter(|l| l.contains("feodotracker"))
        .all(|l| l.ends_with(" 0")));
    assert!(!log.contains(SECRET), "{log}");
    assert!(!stderr_of(&output).contains(SECRET));
    assert_eq!(stderr_of(&output).matches("auth file").count(), 0);
    Ok(())
}

/// PK-143, key file 0644: the key is not used, one `[warn]` names the file.
#[test]
fn a_loose_key_file_is_not_used_and_is_warned_about_once() -> TestResult {
    let dir = fresh_dir("key0644")?;
    let key = write_key(&dir, 0o644)?;
    let (output, log) = run_with_fake_curl(&dir, Some(&key))?;
    assert_eq!(requests_to(&log, "threatfox.abuse.ch"), 0, "{log}");
    assert_eq!(requests_to(&log, "urlhaus.abuse.ch"), 0, "{log}");
    assert!(!log.lines().any(|line| line.ends_with(" 1")), "{log}");
    let stderr = stderr_of(&output);
    assert_eq!(stderr.matches("has mode 644").count(), 1, "{stderr}");
    assert!(!stderr.contains(SECRET));
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
