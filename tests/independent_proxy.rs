//! 独立検算。段階7「proxy」の PK-70〜73・PK-75・PK-78 相当を自動化する
//! （PK-70〜75 本体は実機で curl を打つ手順。`docs/design.md`「段階7 proxy」
//! 節「受入 ID（PK-70〜PK-75）」。ここでは `127.0.0.1:0` の ephemeral port と
//! 偽の上流を使い、`cargo test` の下で並列に走っても port を奪い合わない
//! 形にする。root は要らない）。
//!
//! `packetdeath::proxy::{bind, serve, AllowFrom}` の公開 API だけを使う。
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
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

/// `tests/` 配下だけに書く一時 file（`independent_reload.rs::scratch_path`
/// と同じ判断）。test 名ごとに別 path にして、並列実行する `cargo test` の
/// 下でも file を奪い合わないようにする。
fn scratch_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/tmp-independent-proxy");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(name))
}

/// `bind` して即 `serve` を別 thread で起動し、実際に bind できた port を
/// 含む `SocketAddr` を返す。`serve` は無限 loop なので thread は test
/// process の終了まで残るが、他の `run_*` loop と同じく Ctrl-C 相当が無い
/// 前提であり、test process の終了と共に消える。`limits` を呼び出し側から
/// 渡せるようにしてあるのは、本番値（30秒・300秒・256本）だと timeout 系の
/// test が遅くなるため。
fn start_proxy(
    blocklist: &str,
    log_path: PathBuf,
    limits: ProxyLimits,
) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = proxy::bind("127.0.0.1:0".parse()?)?;
    let addr = listener.local_addr()?;
    let blocklist = Blocklist::parse(blocklist);
    let allowlist = Allowlist::empty();
    let log = FlowLogSink::open(&log_path)?;
    let allow_from = AllowFrom::from_args(&[]);

    std::thread::spawn(move || {
        // `av` は `serve` が生きている間 借用され続けるため、この thread の
        // 中で所有する（`WatchInputs<'a>` の `'a` を、この thread の stack
        // frame に閉じ込める）。
        let av = AvList::empty();
        let inputs = WatchInputs::new(blocklist, allowlist, None, IpList::empty(), &av);
        proxy::serve(listener, &allow_from, &log, inputs, limits, None);
    });
    Ok(addr)
}

fn spawn_echo_server() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    Ok(addr)
}

/// テスト項目：blocklist 無しの CONNECT が `200` を返し、byte が双方向に
/// 届く（PK-70 の陰性対照と PK-72「当たらない CONNECT が通る」の中身）。
#[test]
fn connect_without_blocklist_tunnels_bytes_both_ways() -> TestResult {
    let upstream_addr = spawn_echo_server()?;
    let log_path = scratch_path("connect-pass.jsonl")?;
    let proxy_addr = start_proxy("", log_path, ProxyLimits::default())?;

    let mut client = TcpStream::connect(proxy_addr)?;
    write!(
        client,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    )?;

    let mut response = [0u8; 128];
    let n = client.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "200 を返さなかった: {response:?}"
    );

    client.write_all(b"hello")?;
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed)?;
    assert_eq!(&echoed, b"hello", "byte が往復しなかった");
    Ok(())
}

/// テスト項目：blocklist に当たる CONNECT が `403` を返し、上流（偽の
/// TcpListener）への接続が1件も届かない（PK-71 相当）。
#[test]
fn blocklisted_connect_gets_403_and_upstream_sees_zero_connections() -> TestResult {
    let fake_upstream = TcpListener::bind("127.0.0.1:0")?;
    let upstream_port = fake_upstream.local_addr()?.port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(fake_upstream.accept().is_ok());
    });

    let log_path = scratch_path("connect-block.jsonl")?;
    // 既定は `Blackhole` へ変わったため、この test は従来どおりの `403`
    // 前提を保つために `deny: Forbid` を明示する。
    let limits = ProxyLimits {
        deny: DenyMode::Forbid,
        ..ProxyLimits::default()
    };
    let proxy_addr = start_proxy("127.0.0.1\n", log_path.clone(), limits)?;

    let mut client = TcpStream::connect(proxy_addr)?;
    write!(
        client,
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    )?;

    let mut response = [0u8; 128];
    let n = client.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "403 を返さなかった: {response:?}"
    );

    let accepted = rx.recv_timeout(Duration::from_millis(300));
    assert!(
        accepted.is_err(),
        "blocklist に当たったのに上流へ接続が届いた"
    );

    let flows = std::fs::read_to_string(&log_path)?;
    assert!(
        flows.contains("\"decision\":\"block\"") && flows.contains("\"reason\":\"sni\""),
        "flows.jsonl に block/sni が記録されていない: {flows:?}"
    );
    Ok(())
}

/// テスト項目：平文 HTTP の絶対 URL（`GET http://host/path HTTP/1.1`）が、
/// 上流には相対 path で届く（PK-75 の「host で判定される」の後半・実際の
/// 転送を測る）。
#[test]
fn plain_http_absolute_url_is_forwarded_with_relative_path() -> TestResult {
    let (tx, rx) = mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let upstream_addr = listener.local_addr()?;
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
    });

    let log_path = scratch_path("plain-http.jsonl")?;
    let proxy_addr = start_proxy("", log_path, ProxyLimits::default())?;

    let mut client = TcpStream::connect(proxy_addr)?;
    write!(
        client,
        "GET http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    )?;

    let received = rx.recv_timeout(Duration::from_secs(2))?;
    assert!(
        received.starts_with("GET /hello HTTP/1.1"),
        "相対 path で転送されていない: {received:?}"
    );
    Ok(())
}

/// テスト項目：request 行を1 byte も送らない client を `request_read_timeout`
/// の経過後に切り、`active` の枠を解放する。
/// `max_concurrent_connections: 1` にして、枠を奪われている間は
/// 正規の CONNECT が `503` になり、timeout 後は `503` でなく `200` になる
/// ことで確かめる。本番値（30秒・256本）だと test が遅くなるので、
/// `ProxyLimits` に短い値を明示的に渡す。
#[test]
fn idle_client_is_timed_out_and_releases_the_connection_slot() -> TestResult {
    let upstream_addr = spawn_echo_server()?;
    let log_path = scratch_path("idle-timeout.jsonl")?;
    let limits = ProxyLimits {
        request_read_timeout: Duration::from_millis(500),
        pipe_idle_timeout: Duration::from_millis(500),
        max_concurrent_connections: 1,
        ..ProxyLimits::default()
    };
    let proxy_addr = start_proxy("", log_path, limits)?;

    // 唯一の枠を、何も送らない client で埋める。この test の終わりまで
    // drop しない（drop すると別経路で接続が閉じてしまい、
    // `request_read_timeout` を測ったことにならない）。
    let idle_client = TcpStream::connect(proxy_addr)?;
    // accept loop（単一 thread）が idle_client を処理して `active` を
    // 1 に上げるのを待つ（TCP の connect() 自体は accept() より先に
    // 完了し得るため、次の connect との順序を保証するための待ち）。
    std::thread::sleep(Duration::from_millis(100));

    // 枠が埋まっている間に来た正規の CONNECT は 503 で拒否される
    // （陽性対照：これが 503 にならないなら、そもそも枠を奪えていない）。
    let mut blocked = TcpStream::connect(proxy_addr)?;
    write!(
        blocked,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    )?;
    let mut response = [0u8; 128];
    let n = blocked.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "枠が埋まっているのに 503 を返さなかった: {response:?}"
    );

    // `request_read_timeout`（500 ms）の経過を待つ。
    std::thread::sleep(Duration::from_millis(900));

    // 枠が解放されたので、次の正規 CONNECT は 503 でなく通る
    // （本題：idle client が枠を無期限に食い潰さない）。
    let mut client = TcpStream::connect(proxy_addr)?;
    write!(
        client,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    )?;
    let mut response = [0u8; 128];
    let n = client.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "timeout 後に枠が解放されず、503 のまま: {response:?}"
    );

    drop(idle_client);
    Ok(())
}

/// Sends one raw request and reads until the proxy closes the connection.
fn raw_exchange(proxy_addr: SocketAddr, request: &str) -> Result<String, Box<dyn Error>> {
    let mut client = TcpStream::connect(proxy_addr)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    client.read_to_end(&mut raw)?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// テスト項目（PK-78）：`GET /proxy.pac` が `200` と PAC の content type で
/// 返り、本文が client の繋いだ先（`PROXY 127.0.0.1:<port>; DIRECT`）を
/// 指し、`Content-Length` が本文と一致し、`flows.jsonl` に何も残らない。
/// 陰性対照：他の相対 path は `400` のまま。
#[test]
fn pac_is_served_without_a_flow_log_and_other_paths_stay_400() -> TestResult {
    let log_path = scratch_path("pac.jsonl")?;
    let proxy_addr = start_proxy("", log_path.clone(), ProxyLimits::default())?;

    let response = raw_exchange(
        proxy_addr,
        "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    )?;
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(format!("header と本文の境界が無い: {response:?}").into());
    };
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head:?}");
    assert!(
        head.contains("Content-Type: application/x-ns-proxy-autoconfig"),
        "{head:?}"
    );
    assert!(head.contains("Connection: close"), "{head:?}");
    assert!(
        head.contains(&format!("Content-Length: {}", body.len())),
        "Content-Length が本文と合わない: {head:?}"
    );
    assert!(
        body.contains(&format!("PROXY 127.0.0.1:{}; DIRECT", proxy_addr.port())),
        "{body:?}"
    );

    let other = raw_exchange(proxy_addr, "GET /other HTTP/1.1\r\nHost: x\r\n\r\n")?;
    assert!(other.starts_with("HTTP/1.1 400"), "{other:?}");

    let flows = std::fs::read_to_string(&log_path)?;
    assert!(flows.is_empty(), "PAC が flow log に残った: {flows:?}");
    Ok(())
}

// ------------------------------------------------------------
// blackhole（既定の `--deny`）。block した接続を読んで闇へ捨てる（PK-76・PK-77）。
// ------------------------------------------------------------

/// テスト項目：既定（`DenyMode::Blackhole`）で blocklist に当たる CONNECT が
/// `200 Connection Established` を返し、以後 client から届く byte を読んで
/// 捨て、何も送り返さない（PK-76 の受入本体）。上流（偽の TcpListener）への
/// 接続は1件も届かない。
#[test]
fn blackhole_connect_returns_200_then_reads_silently() -> TestResult {
    let fake_upstream = TcpListener::bind("127.0.0.1:0")?;
    let upstream_port = fake_upstream.local_addr()?.port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(fake_upstream.accept().is_ok());
    });

    let log_path = scratch_path("blackhole-connect.jsonl")?;
    // `ProxyLimits::default()` の `deny` は `DenyMode::Blackhole`（既定）。
    let proxy_addr = start_proxy("127.0.0.1\n", log_path.clone(), ProxyLimits::default())?;

    let mut client = TcpStream::connect(proxy_addr)?;
    write!(
        client,
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    )?;

    let mut response = [0u8; 128];
    let n = client.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "blackhole が 200 Connection Established を返さなかった: {response:?}"
    );

    // 何も送り返さない ── 1秒 待っても byte が届かないことを確かめる。
    client.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut buf = [0u8; 16];
    match client.read(&mut buf) {
        Ok(n) => return Err(format!("blackhole のはずなのに byte が届いた: {n} bytes").into()),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
        Err(e) => return Err(format!("予期しない error: {e}").into()),
    }

    let accepted = rx.recv_timeout(Duration::from_millis(300));
    assert!(
        accepted.is_err(),
        "blackhole のはずなのに上流へ接続が届いた"
    );

    let flows = std::fs::read_to_string(&log_path)?;
    assert!(
        flows.contains("\"decision\":\"block\"") && flows.contains("\"reason\":\"sni\""),
        "flows.jsonl に block/sni が記録されていない: {flows:?}"
    );
    Ok(())
}

/// テスト項目：blackhole に移った接続は一般枠（`active`）を占有し続けない。
/// `max_concurrent_connections: 1` で一般枠を
/// 1本しか許さない状態でも、1本目（blackhole 入り）の後に来た正規の
/// CONNECT が `503`（枠満杯）でなく `200` になることで、一般枠が
/// 解放されたことを確かめる。
#[test]
fn blackhole_connection_frees_the_general_slot() -> TestResult {
    let upstream_addr = spawn_echo_server()?;

    let log_path = scratch_path("blackhole-slot.jsonl")?;
    let limits = ProxyLimits {
        max_concurrent_connections: 1,
        max_blackhole_connections: 1,
        blackhole_hold: Duration::from_secs(10),
        ..ProxyLimits::default()
    };
    // blocklist は 127.0.0.2 だけに当てる。1本目はこの IP 宛の CONNECT で
    // blackhole に入り、2本目は blocklist に当たらない 127.0.0.1 宛の
    // CONNECT にする ── 両方を 127.0.0.1 にすると blocklist が全接続に
    // 当たってしまい、枠の付け替えだけを切り出して測れない。127.0.0.2 は
    // loopback の範囲（127.0.0.0/8）内なので name resolution 無しで
    // そのまま宛先として読め、block されるので実際に TCP は張らない。
    let proxy_addr = start_proxy("127.0.0.2\n", log_path, limits)?;

    // 1本目：blocklist に当たる CONNECT。blackhole に入り `200` を返す。
    let mut blocked_client = TcpStream::connect(proxy_addr)?;
    write!(
        blocked_client,
        "CONNECT 127.0.0.2:9 HTTP/1.1\r\nHost: 127.0.0.2:9\r\n\r\n"
    )?;
    let mut response = [0u8; 128];
    let n = blocked_client.read(&mut response)?;
    assert!(
        String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"),
        "1本目が blackhole の 200 を返さなかった"
    );

    // accept loop（単一 thread）が blackhole 経路の枠付け替え
    // （`active.fetch_sub` の後 `run_blackhole` に入る）まで進むのを待つ。
    std::thread::sleep(Duration::from_millis(100));

    // 2本目：blocklist に当たらない正規の CONNECT。一般枠は1本しかないが、
    // 1本目が blackhole へ付け替わって解放済みなら 503 でなく 200 になる。
    let mut client = TcpStream::connect(proxy_addr)?;
    write!(
        client,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    )?;
    let mut response = [0u8; 128];
    let n = client.read(&mut response)?;
    let response = String::from_utf8_lossy(&response[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "枠の付け替えが効いておらず 503 のまま: {response:?}"
    );

    drop(blocked_client);
    Ok(())
}

/// テスト項目（PK-77 の oracle）：`blackhole_hold` 経過後に接続が閉じられ
/// （client の read が EOF）、blackhole 枠が解放される。
/// `max_blackhole_connections: 1` で枠を1本に絞り、1本目の hold 経過を
/// 待ってから2本目の block CONNECT を送ると、枠が解放されていれば
/// `403`（満杯）でなく `200`（blackhole 入り）になる。
#[test]
fn blackhole_hold_expires_and_releases_the_blackhole_slot() -> TestResult {
    let fake_upstream = TcpListener::bind("127.0.0.1:0")?;
    let upstream_port = fake_upstream.local_addr()?.port();
    std::thread::spawn(move || {
        let _ = fake_upstream.accept();
    });

    let log_path = scratch_path("blackhole-hold-expire.jsonl")?;
    let limits = ProxyLimits {
        max_blackhole_connections: 1,
        blackhole_hold: Duration::from_millis(500),
        ..ProxyLimits::default()
    };
    let proxy_addr = start_proxy("127.0.0.1\n", log_path, limits)?;

    // 1本目：blackhole へ入る。EOF を送らずに持ったまま hold 経過を待つ。
    let mut first = TcpStream::connect(proxy_addr)?;
    write!(
        first,
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    )?;
    let mut response = [0u8; 128];
    let n = first.read(&mut response)?;
    assert!(
        String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 200"),
        "1本目が blackhole の 200 を返さなかった"
    );

    // proxy 側は client の EOF を待たず、hold（500ms）経過だけで閉じる
    // （PK-77 の本題：時間無制限に黙らない）。
    std::thread::sleep(Duration::from_millis(900));

    // proxy 側が閉じた印として、`first` の read が EOF になっているはず。
    let mut buf = [0u8; 1];
    let n = first.read(&mut buf)?;
    assert_eq!(n, 0, "hold 経過後も proxy 側が接続を閉じていない");

    // 2本目：枠が解放されていれば 403（満杯）でなく 200（blackhole 入り）。
    let mut second = TcpStream::connect(proxy_addr)?;
    write!(
        second,
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    )?;
    let mut response2 = [0u8; 128];
    let n2 = second.read(&mut response2)?;
    let response2 = String::from_utf8_lossy(&response2[..n2]);
    assert!(
        response2.starts_with("HTTP/1.1 200"),
        "hold 経過後も blackhole 枠が解放されず 403 のまま: {response2:?}"
    );

    Ok(())
}
