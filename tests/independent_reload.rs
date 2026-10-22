//! 独立検算。サービスを再起動せずに blocklist / allowlist の書き換えを
//! 反映することの受入。`src/reload.rs` の公開 API
//! （`ReloadWatcher` / `ReloadOutcome` / `apply`）だけを使う。
//! 末尾の PK-91〜PK-93（`docs/design.md`「段階9 malware feed」）だけは、複数
//! file の和集合と iplist の読み直しを proxy 経由（`proxy::serve` が
//! `WatchInputs` を回す）で測る。
//!
//! # `unwrap()` / `expect()` を使わない
//! 各 test は `Result<(), Box<dyn std::error::Error>>` を返し、`?` で伝播する。

use packetdeath::allowlist::Allowlist;
use packetdeath::av::AvList;
use packetdeath::block_loop::WatchInputs;
use packetdeath::blocklist::Blocklist;
use packetdeath::flow::FlowLogSink;
use packetdeath::iplist::IpList;
use packetdeath::proxy::{self, AllowFrom, DenyMode, ProxyLimits};
use packetdeath::reload::{self, ReloadOutcome, ReloadWatcher};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

/// `tests/` 配下だけに書く一時 file（要求範囲内。`independent_log_format.rs`
/// の `scratch_path` と同じ判断）。test 名ごとに別 path にして、並列実行
/// する `cargo test` の下でも file を奪い合わないようにする。
fn scratch_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tmp-independent-reload");
    fs::create_dir_all(&dir)?;
    Ok(dir.join(name))
}

/// テスト項目1：file を書き換えたら、新しい内容で判定されること。
#[test]
fn rewriting_the_file_is_detected_and_reparsed() -> TestResult {
    let path = scratch_path("rewrite.txt")?;
    fs::write(&path, "old.example\n")?;
    let mut watcher = ReloadWatcher::new(path.clone());
    let mut blocklist = Blocklist::parse("old.example\n");

    // mtime の解像度に依存しないよう、内容と byte 数の両方を変える。
    std::thread::sleep(Duration::from_millis(20));
    fs::write(&path, "new.example\nold.example\n")?;

    reload::apply(
        &mut watcher,
        &mut blocklist,
        "blocklist",
        Blocklist::parse,
        Blocklist::len,
    );

    assert!(
        blocklist.matches("new.example"),
        "書き換え後の内容が反映されていない"
    );
    Ok(())
}

/// テスト項目2：file を消しても落ちないこと（前の内容を使い続ける）。
#[test]
fn removing_the_file_keeps_previous_content_and_does_not_panic() -> TestResult {
    let path = scratch_path("removed.txt")?;
    fs::write(&path, "kept.example\n")?;
    let mut watcher = ReloadWatcher::new(path.clone());
    let mut blocklist = Blocklist::parse("kept.example\n");

    fs::remove_file(&path)?;
    reload::apply(
        &mut watcher,
        &mut blocklist,
        "blocklist",
        Blocklist::parse,
        Blocklist::len,
    );

    assert!(
        blocklist.matches("kept.example"),
        "file が消えたのに前の内容が失われた"
    );
    Ok(())
}

/// テスト項目3：壊れた内容（不正 UTF-8）を書いても落ちないこと。
#[test]
fn writing_invalid_utf8_keeps_previous_content_and_does_not_panic() -> TestResult {
    let path = scratch_path("broken.txt")?;
    fs::write(&path, "kept.example\n")?;
    let mut watcher = ReloadWatcher::new(path.clone());
    let mut blocklist = Blocklist::parse("kept.example\n");

    std::thread::sleep(Duration::from_millis(20));
    fs::write(&path, [0xff, 0xfe, 0x00, 0x01])?;
    reload::apply(
        &mut watcher,
        &mut blocklist,
        "blocklist",
        Blocklist::parse,
        Blocklist::len,
    );

    assert!(
        blocklist.matches("kept.example"),
        "壊れた内容を読んだ後に前の内容が失われた"
    );
    Ok(())
}

/// テスト項目4：変わっていないときは読み直さないこと（log が溢れないため）。
#[test]
fn unchanged_file_yields_unchanged_on_every_poll() -> TestResult {
    let path = scratch_path("stable.txt")?;
    fs::write(&path, "stable.example\n")?;
    let mut watcher = ReloadWatcher::new(path);

    assert!(matches!(watcher.poll(), ReloadOutcome::Unchanged));
    assert!(matches!(watcher.poll(), ReloadOutcome::Unchanged));
    assert!(matches!(watcher.poll(), ReloadOutcome::Unchanged));
    Ok(())
}

/// 陽性対照：`ReloadWatcher::new` の直後は construct 時点の内容を
/// 覚えている（construct 前の状態が「変化」として誤検知されない）。
#[test]
fn positive_control_freshly_constructed_watcher_is_unchanged() -> TestResult {
    let path = scratch_path("fresh.txt")?;
    fs::write(&path, "fresh.example\n")?;
    let mut watcher = ReloadWatcher::new(path);
    assert!(matches!(watcher.poll(), ReloadOutcome::Unchanged));
    Ok(())
}

/// `--blocklist` / `--iplist` を複数 file で渡した `proxy` を `127.0.0.1:0`
/// で起動する（`main.rs` の `build_watch_inputs` と同じ組み立て）。block は
/// `403` で返させ、応答の形を固定する。
fn start_proxy_with_files(
    blocklists: &[PathBuf],
    iplists: &[PathBuf],
    log_path: &std::path::Path,
) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = proxy::bind("127.0.0.1:0".parse()?)?;
    let addr = listener.local_addr()?;
    let blocklists = Blocklist::load_all(blocklists);
    let iplists = IpList::load_all(iplists);
    let log = FlowLogSink::open(log_path)?;
    let allow_from = AllowFrom::from_args(&[]);
    let limits = ProxyLimits {
        deny: DenyMode::Forbid,
        ..ProxyLimits::default()
    };
    std::thread::spawn(move || {
        let av = AvList::empty();
        let inputs = WatchInputs::new(
            Blocklist::empty(),
            Allowlist::empty(),
            None,
            IpList::empty(),
            &av,
        )
        .with_blocklist_files(blocklists)
        .with_iplist_files(iplists);
        proxy::serve(listener, &allow_from, &log, inputs, limits, None);
    });
    Ok(addr)
}

/// 1 接続だけ受けて、そのまま閉じる上流。繋がれば `200` の先が在る。
fn spawn_upstream() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    Ok(addr)
}

/// `CONNECT target` を打ち、応答の1行目（`HTTP/1.1 200 ...` など）を返す。
fn connect_status(proxy_addr: SocketAddr, target: &str) -> Result<String, Box<dyn Error>> {
    let mut client = TcpStream::connect(proxy_addr)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        client,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )?;
    let mut buf = [0u8; 128];
    let n = client.read(&mut buf)?;
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let Some(first) = text.lines().next() else {
        return Err(format!("proxy が応答を返さなかった（target={target}）").into());
    };
    Ok(first.to_owned())
}

fn count_in_log(log_path: &std::path::Path, needle: &str) -> Result<usize, Box<dyn Error>> {
    Ok(fs::read_to_string(log_path)?.matches(needle).count())
}

/// PK-91：2本目の blocklist にだけ在る domain が block される。1本目の
/// domain も落ち、どちらにも無い宛先は通る（陰性対照）。
#[test]
fn pk91_domain_only_in_the_second_blocklist_is_blocked() -> TestResult {
    let a = scratch_path("pk91-a.txt")?;
    let b = scratch_path("pk91-b.txt")?;
    fs::write(&a, "a.example\n")?;
    fs::write(&b, "b.example\n")?;
    let log_path = scratch_path("pk91.jsonl")?;
    let _ = fs::remove_file(&log_path);
    let proxy_addr = start_proxy_with_files(&[a, b], &[], &log_path)?;

    assert!(connect_status(proxy_addr, "b.example:443")?.starts_with("HTTP/1.1 403"));
    assert!(connect_status(proxy_addr, "a.example:443")?.starts_with("HTTP/1.1 403"));
    let upstream = spawn_upstream()?;
    let open = connect_status(proxy_addr, &upstream.to_string())?;
    assert!(open.starts_with("HTTP/1.1 200"), "{open:?}");
    assert_eq!(count_in_log(&log_path, "\"reason\":\"sni\"")?, 2);
    Ok(())
}

/// PK-92：2本目の iplist にだけ在る IP 宛てが、reason `iplist` で block される。
/// 陰性対照：1本目だけ（別の IP）なら同じ宛先が通る。
#[test]
fn pk92_ip_only_in_the_second_iplist_is_blocked() -> TestResult {
    let x = scratch_path("pk92-x.txt")?;
    let y = scratch_path("pk92-y.txt")?;
    fs::write(&x, "192.0.2.1\n")?;
    fs::write(&y, "127.0.0.1\n")?;

    let control_log = scratch_path("pk92-control.jsonl")?;
    let _ = fs::remove_file(&control_log);
    let control = start_proxy_with_files(&[], std::slice::from_ref(&x), &control_log)?;
    let upstream = spawn_upstream()?;
    let open = connect_status(control, &upstream.to_string())?;
    assert!(
        open.starts_with("HTTP/1.1 200"),
        "陰性対照が通らない: {open:?}"
    );

    let log_path = scratch_path("pk92.jsonl")?;
    let _ = fs::remove_file(&log_path);
    let proxy_addr = start_proxy_with_files(&[], &[x, y], &log_path)?;
    let upstream = spawn_upstream()?;
    let blocked = connect_status(proxy_addr, &upstream.to_string())?;
    assert!(blocked.starts_with("HTTP/1.1 403"), "{blocked:?}");
    assert_eq!(count_in_log(&log_path, "\"reason\":\"iplist\"")?, 1);
    Ok(())
}

/// PK-93：走行中に iplist を書き換えると、300 ms 後の判定が変わる
/// （PK-74 の iplist 版）。
#[test]
fn pk93_rewriting_the_iplist_while_running_changes_the_verdict() -> TestResult {
    let y = scratch_path("pk93-y.txt")?;
    fs::write(&y, "")?;
    let log_path = scratch_path("pk93.jsonl")?;
    let _ = fs::remove_file(&log_path);
    let proxy_addr = start_proxy_with_files(&[], std::slice::from_ref(&y), &log_path)?;

    let upstream = spawn_upstream()?;
    let before = connect_status(proxy_addr, &upstream.to_string())?;
    assert!(before.starts_with("HTTP/1.1 200"), "{before:?}");

    fs::write(&y, "127.0.0.1\n")?;
    std::thread::sleep(Duration::from_millis(400));
    let upstream = spawn_upstream()?;
    let after = connect_status(proxy_addr, &upstream.to_string())?;
    assert!(after.starts_with("HTTP/1.1 403"), "{after:?}");
    assert_eq!(count_in_log(&log_path, "\"reason\":\"iplist\"")?, 1);
    Ok(())
}
