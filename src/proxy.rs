//! 段階7「proxy」。`docs/design.md`「段階7 proxy」節と受入 ID PK-70〜78 が正本。
//!
//! Runs packetdeath as a CONNECT proxy. Up to stage 7 nothing is decrypted;
//! stage 8 (`crate::mitm`, Linux only) decrypts only the hosts named in
//! `--mitm-list`. 利用者が iPhone 等の
//! 別端末の Wi-Fi proxy 欄へ手で指す（禁じ手2「packetdeath が自分の端末の
//! proxy 設定を書き換える」には当たらない。設計書「段階7 proxy」節）。
//!
//! **Stage 7 does not decrypt TLS; stage 8 decrypts only `--mitm-list`
//! hosts.** `CONNECT host:port HTTP/1.1` の `host` を
//! `SniState::Ok(host)` として既存の同期判定（`judge::run_judges_with_allowlist`）
//! へそのまま渡し、当たらなければ `200 Connection Established` の後は byte を
//! 中継するだけにする。平文 HTTP の絶対 URL（`GET http://host/path HTTP/1.1`）も
//! 同じく `host` を取り出して判定する。
//!
//! `judges` は `SniJudge` / `IpJudge` / `AvJudge` の3つだけを段階の番号順
//! （sni=2, iplist=5, av=6）で評価する。`CnameJudge`（段階3）と
//! `IdsJudge`（段階4）は proxy に無い（`cname_matched_qnames` は常に空集合）。
//!
//! `std::thread::scope` で接続ごとの thread を切る。`tokio` は足さない
//! （`block` / `observe` が全部 同期で書かれているのと同じ理由。設計書
//! 「段階7 proxy」節）。

use crate::block_loop::WatchInputs;
use crate::flow::{FlowKey, FlowLogEntry, FlowLogSink, Proto, DECISION_BLOCK, DECISION_PASS};
use crate::judge::{
    run_judges_with_allowlist, AvJudge, IpJudge, Judge, JudgeInput, Reason, SniJudge,
};
use crate::sni::SniState;
use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// blocklist / allowlist の走行中 読み直しを確かめる間隔。`linux.rs` の
/// `RELOAD_POLL_INTERVAL` と同じ 300 ms を踏襲する（`docs/design.md`
/// 「走行中の読み直し」節）。
const RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// 上流への TCP 接続確立を待つ上限。`docs/design.md`「段階7 proxy」節の
/// 「上流へ TcpStream::connect（timeout を置く）」に応える。
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// block 判定を返す形。CONNECT の1行で判定して `403` を返すと、相手は広告が
/// 見られていないことに気づく。それを避けるため
/// `Blackhole` が既定 ── 繋がったふりをして（`200 Connection Established`
/// を返して）以後 client から届く byte を読んで捨て、何も送り返さない。
/// No fake response is sent: this path never decrypts, so it could not even
/// forge one the client would trust (a blocked host is never handed to stage 8).
/// `Forbid` は既存の `403` の
/// まま残す（`--deny 403` で明示的に選ぶ。既存 test はこちら）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMode {
    /// 繋がったふりをして byte を読み捨てる（既定）。
    Blackhole,
    /// `403 Forbidden` を返して閉じる（従来どおり）。
    Forbid,
}

impl std::str::FromStr for DenyMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blackhole" => Ok(Self::Blackhole),
            "403" => Ok(Self::Forbid),
            _ => Err(()),
        }
    }
}

/// `Blackhole` の1接続を hold する上限の既定値。時間無制限に黙ると socket と
/// thread を食い潰す（採らない手段）ので、この時間か
/// client の EOF のどちらか早い方で閉じる。
const DEFAULT_BLACKHOLE_HOLD: Duration = Duration::from_secs(60);

/// 同時に hold する blackhole 接続数の上限の既定値。一般枠（`active`）とは
/// 別に持つ（`docs/design.md`「段階7 proxy」節）。
const DEFAULT_MAX_BLACKHOLE_CONNECTIONS: usize = 256;

/// 同時に処理する接続数の上限の既定値。iPhone 等の少数端末が使う個人用途の
/// proxy であり、fd と thread を無制限に食う事故を防ぐための固定上限。
/// `ProxyLimits::default()` が使う。
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// request 行・header 行1行あたりの上限（8 KiB。`docs/design.md`「段階7
/// proxy」節）。外から来た byte を信じない（`sni.rs` と同じ方針）。
const MAX_LINE_BYTES: usize = 8 * 1024;

/// header の総行数の上限。1行あたりの上限だけでは、大量の短い header 行で
/// `Vec` が際限なく育つ事故を防げない。Stage 8 applies the same limit to
/// decrypted heads (`mitm.rs`).
pub(crate) const MAX_HEADER_LINES: usize = 100;

/// Stage 8's running state, handed to [`serve`]. Decryption exists on Linux
/// only (`Cargo.toml` keeps the TLS crates there); elsewhere this type has no
/// value, so `serve` can only ever receive `None`.
#[cfg(target_os = "linux")]
pub use crate::mitm::Mitm;

/// Stage 8's running state, handed to [`serve`]. Decryption exists on Linux
/// only; on this target the type has no value, so `serve` gets `None`.
#[cfg(not(target_os = "linux"))]
pub enum Mitm {}

/// request 行（＝ CONNECT/GET の1行目）を client が送ってくるまで待つ上限の
/// 既定値。繋ぎっぱなしで何も送らない client が thread と `active` の枠を
/// 無期限に食い潰すのを防ぐ。この値は
/// `set_read_timeout` に渡すだけで、判定（fail-open）の意味は変えない ──
/// 詰まった接続を切るだけである。`ProxyLimits::default()` が使う。
const DEFAULT_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// `200 Connection Established` / 転送開始後、client・上流のどちらかが
/// 無通信のまま繋ぎっぱなしにされる時間の上限の既定値。timeout で
/// `io::copy` が `Err`（`WouldBlock`/`TimedOut`）を返したら
/// `pipe_bidirectional` が両側を shutdown して抜ける。
/// `ProxyLimits::default()` が使う。
const DEFAULT_PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// `bind` / `serve` へ渡す、接続まわりの上限をまとめた設定。test が本番値
/// （30秒・300秒・256本）を待つと遅くなるため、明示的に渡せる形にする
/// （test は 1 秒 などの短い値を渡す）。
#[derive(Debug, Clone, Copy)]
pub struct ProxyLimits {
    /// request 行を待つ上限。
    pub request_read_timeout: Duration,
    /// 中継確立後の無通信を許す上限。
    pub pipe_idle_timeout: Duration,
    /// 同時に処理する接続数の上限。
    pub max_concurrent_connections: usize,
    /// block 判定を返す形（`--deny`）。既定は `Blackhole`。
    pub deny: DenyMode,
    /// `Blackhole` の1接続を hold する上限。
    pub blackhole_hold: Duration,
    /// 同時に hold する blackhole 接続数の上限。
    pub max_blackhole_connections: usize,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            request_read_timeout: DEFAULT_REQUEST_READ_TIMEOUT,
            pipe_idle_timeout: DEFAULT_PIPE_IDLE_TIMEOUT,
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            deny: DenyMode::Blackhole,
            blackhole_hold: DEFAULT_BLACKHOLE_HOLD,
            max_blackhole_connections: DEFAULT_MAX_BLACKHOLE_CONNECTIONS,
        }
    }
}

/// How long the accept loop waits after a failed `accept()` (for example fd
/// exhaustion) before it tries again, so the loop does not spin on the CPU.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// 未指定時の `--allow-from` 既定値：loopback と RFC1918。
const DEFAULT_ALLOW_FROM: [&str; 5] = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

#[derive(Debug)]
pub enum ProxyError {
    Bind(SocketAddr, io::Error),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locale = crate::i18n::locale();
        match self {
            Self::Bind(addr, e) => {
                write!(
                    f,
                    "{}",
                    crate::i18n::proxy_listen_bind_failed(locale, addr, e)
                )
            }
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind(_, e) => Some(e),
        }
    }
}

/// `listen_addr` を bind するだけの1段階目。`serve` と分けているのは、
/// `--listen 127.0.0.1:0`（OS が空き port を選ぶ）を使う test が
/// `TcpListener::local_addr()` で実際の port を読めるようにするため。
pub fn bind(listen_addr: SocketAddr) -> Result<TcpListener, ProxyError> {
    TcpListener::bind(listen_addr).map_err(|e| ProxyError::Bind(listen_addr, e))
}

/// IPv4/IPv6 の CIDR。`iplist.rs` の private な `Cidr` と同じ発想
/// （`to_bits` によるマスク比較）だが、`iplist.rs` の型は
/// 共有せず、`--allow-from` 専用に最小限で持つ。
#[derive(Debug, Clone, Copy)]
enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Cidr {
    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(v4)) => {
                masked_eq_u32(v4.to_bits(), *network, *prefix)
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(v6)) => {
                masked_eq_u128(v6.to_bits(), *network, *prefix)
            }
            _ => false,
        }
    }
}

fn masked_eq_u32(addr: u32, network: u32, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    addr & mask == network & mask
}

fn masked_eq_u128(addr: u128, network: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - u32::from(prefix));
    addr & mask == network & mask
}

fn parse_cidr(input: &str) -> Option<Cidr> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let (addr_part, prefix_part) = match input.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (input, None),
    };
    let addr: IpAddr = addr_part.parse().ok()?;
    match addr {
        IpAddr::V4(v4) => {
            let prefix = match prefix_part {
                Some(p) => p.parse::<u8>().ok().filter(|&p| p <= 32)?,
                None => 32,
            };
            Some(Cidr::V4 {
                network: v4.to_bits(),
                prefix,
            })
        }
        IpAddr::V6(v6) => {
            let prefix = match prefix_part {
                Some(p) => p.parse::<u8>().ok().filter(|&p| p <= 128)?,
                None => 128,
            };
            Some(Cidr::V6 {
                network: v6.to_bits(),
                prefix,
            })
        }
    }
}

/// `--allow-from` に渡す CIDR の集合。`--listen` は LAN へ開くので、
/// 接続元を制限する（open proxy 対策。`docs/design.md`「段階7 proxy」節）。
pub struct AllowFrom {
    entries: Vec<Cidr>,
}

impl AllowFrom {
    fn default_private() -> Self {
        Self {
            entries: DEFAULT_ALLOW_FROM
                .iter()
                .filter_map(|s| parse_cidr(s))
                .collect(),
        }
    }

    /// `raw` が空なら既定（loopback と RFC1918）を使う。1件でも渡されたら
    /// 既定へは倒さない ── parse に失敗した値を読み飛ばした結果 空集合に
    /// なっても、deny-all のままにする（open proxy 対策を弱める方向へは
    /// 絶対に倒さない）。
    pub fn from_args(raw: &[String]) -> Self {
        let locale = crate::i18n::locale();
        if raw.is_empty() {
            eprintln!(
                "packetdeath: [info] {}",
                crate::i18n::proxy_allow_from_default_used(locale)
            );
            return Self::default_private();
        }
        let entries: Vec<Cidr> = raw
            .iter()
            .filter_map(|s| match parse_cidr(s) {
                Some(cidr) => Some(cidr),
                None => {
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::proxy_allow_from_invalid(locale, s)
                    );
                    None
                }
            })
            .collect();
        eprintln!(
            "packetdeath: [info] {}",
            crate::i18n::proxy_allow_from_configured(locale, entries.len())
        );
        Self { entries }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.entries.iter().any(|c| c.contains(&ip))
    }
}

/// CONNECT / 絶対 URL の request 行から取り出した宛先。
enum RequestTarget {
    Connect {
        host: String,
        port: u16,
    },
    Absolute {
        method: String,
        host: String,
        port: u16,
        path: String,
        version: String,
    },
}

impl RequestTarget {
    fn host(&self) -> &str {
        match self {
            Self::Connect { host, .. } | Self::Absolute { host, .. } => host,
        }
    }

    fn port(&self) -> u16 {
        match self {
            Self::Connect { port, .. } | Self::Absolute { port, .. } => *port,
        }
    }
}

/// `CONNECT` の target（`host:port` か `[ipv6]:port`）を分ける。port は必須。
fn parse_connect_target(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port: u16 = after.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port_str) = target.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

/// 絶対 URL（`http://host[:port]/path`）の authority を分ける。port 省略時は
/// 既定の 80。
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => 80,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port_str)) => Some((host.to_string(), port_str.parse().ok()?)),
        None => Some((authority.to_string(), 80)),
    }
}

/// `CONNECT host:port HTTP/1.x` か `<METHOD> http://host[:port]/path HTTP/1.x`
/// のどちらかだけを受け付ける。それ以外（相対 path、`CONNECT` の port 欠落等）は
/// `None`（呼び出し側が `400` へ倒す）。
fn parse_request_line(line: &str) -> Option<RequestTarget> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_connect_target(target)?;
        if host.is_empty() {
            return None;
        }
        return Some(RequestTarget::Connect { host, port });
    }

    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = parse_authority(authority)?;
    if host.is_empty() {
        return None;
    }
    Some(RequestTarget::Absolute {
        method: method.to_string(),
        host,
        port,
        path: path.to_string(),
        version: version.to_string(),
    })
}

/// 1行を読んだ結果。
pub(crate) enum LineOutcome {
    Line(String),
    /// client が何も送らずに切った（あるいは行の途中で切った）。
    Eof,
    /// `MAX_LINE_BYTES` を超えても改行が来なかった。
    TooLong,
}

/// 1行（`\n` まで。末尾の `\r` は取り除く）を `MAX_LINE_BYTES` の上限つきで
/// 読む。**外から来た byte を信じない**（`sni.rs` と同じ方針）。Stage 8 reads
/// decrypted heads and chunk-size lines with it too (`mitm.rs`).
pub(crate) fn read_capped_line(reader: &mut impl BufRead) -> LineOutcome {
    let mut buf = Vec::new();
    let mut limited = reader.take(MAX_LINE_BYTES as u64 + 1);
    match limited.read_until(b'\n', &mut buf) {
        Ok(0) => LineOutcome::Eof,
        Err(_) => LineOutcome::Eof,
        Ok(_) => {
            if buf.len() > MAX_LINE_BYTES || buf.last() != Some(&b'\n') {
                return LineOutcome::TooLong;
            }
            buf.pop(); // '\n'
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            LineOutcome::Line(String::from_utf8_lossy(&buf).into_owned())
        }
    }
}

/// request 行と header を読み、`(target, headers)` を返す。parse できない・
/// 長すぎる・header が多すぎるときは `400` を返してから `None`。client が
/// 何も送らずに切った（EOF）ときも `None`（何も返さない。port scan 等の
/// 雑音を warn で埋めない）。
fn read_request(
    reader: &mut BufReader<TcpStream>,
    peer: SocketAddr,
    mitm: Option<&Mitm>,
) -> Option<(RequestTarget, Vec<String>)> {
    let locale = crate::i18n::locale();

    let request_line = match read_capped_line(reader) {
        LineOutcome::Eof => return None,
        LineOutcome::TooLong => {
            eprintln!(
                "packetdeath: [warn] {}",
                crate::i18n::proxy_request_line_too_long(locale, peer.ip())
            );
            respond_status(reader.get_mut(), 400, "Bad Request");
            return None;
        }
        LineOutcome::Line(line) => line,
    };

    // The PAC request is not a flow: it is answered here and never judged or
    // logged. Headers are read (and dropped) first so the client has sent the
    // whole request before the response is written.
    if is_pac_request(&request_line) {
        read_headers(reader, peer)?;
        serve_pac(reader.get_mut(), peer);
        return None;
    }

    // Same for `/ca.crt`, but only while decryption is on. Without it the line
    // falls through untouched to the `400` below, like any other relative path.
    if is_ca_request(&request_line) {
        if let Some(pem) = ca_pem(mitm) {
            read_headers(reader, peer)?;
            serve_ca(reader.get_mut(), peer, pem);
            return None;
        }
    }

    let target = match parse_request_line(&request_line) {
        Some(t) => t,
        None => {
            eprintln!(
                "packetdeath: [warn] {}",
                crate::i18n::proxy_request_unparseable(locale, peer.ip())
            );
            respond_status(reader.get_mut(), 400, "Bad Request");
            return None;
        }
    };

    let headers = read_headers(reader, peer)?;
    Some((target, headers))
}

/// Reads header lines up to the blank line. Same failure contract as
/// `read_request`: too long or too many lines answers `400` and returns
/// `None`; an EOF returns `None` silently.
fn read_headers(reader: &mut BufReader<TcpStream>, peer: SocketAddr) -> Option<Vec<String>> {
    let locale = crate::i18n::locale();
    let mut headers = Vec::new();
    loop {
        match read_capped_line(reader) {
            LineOutcome::Eof => return None,
            LineOutcome::TooLong => {
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::proxy_request_line_too_long(locale, peer.ip())
                );
                respond_status(reader.get_mut(), 400, "Bad Request");
                return None;
            }
            LineOutcome::Line(line) if line.is_empty() => return Some(headers),
            LineOutcome::Line(line) => {
                if headers.len() >= MAX_HEADER_LINES {
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::proxy_request_unparseable(locale, peer.ip())
                    );
                    respond_status(reader.get_mut(), 400, "Bad Request");
                    return None;
                }
                headers.push(line);
            }
        }
    }
}

/// The path a client fetches its proxy auto-config from.
const PAC_PATH: &str = "/proxy.pac";

/// Fixed part of the PAC file. Names are matched by suffix and IPv4 literals
/// by range, so no `dnsResolve` runs (a lookup per connection is slow on iOS).
/// ES3 only (`var`, no arrow functions): older WinHTTP script engines read it.
/// IPv6 literals carry no `.`, so `isPlainHostName` sends them DIRECT.
const PAC_HEAD: &str = "function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host === \"localhost\" ||
      shExpMatch(host, \"*.local\") || shExpMatch(host, \"*.lan\") ||
      shExpMatch(host, \"*.home\")) {
    return \"DIRECT\";
  }
  var m = /^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/.exec(host);
  if (m) {
    var a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) || (a === 169 && b === 254)) {
      return \"DIRECT\";
    }
  }
";

/// The path a client fetches the proxy CA certificate from. One fixed path:
/// nothing else under `--ca-dir` (the key above all) is reachable.
const CA_PATH: &str = "/ca.crt";

/// `GET <path> HTTP/1.x` and nothing else (no query, no other method).
fn is_plain_get(line: &str, path: &str) -> bool {
    let mut parts = line.split_whitespace();
    parts.next() == Some("GET")
        && parts.next() == Some(path)
        && parts.next().is_some_and(|v| v.starts_with("HTTP/"))
        && parts.next().is_none()
}

fn is_pac_request(line: &str) -> bool {
    is_plain_get(line, PAC_PATH)
}

fn is_ca_request(line: &str) -> bool {
    is_plain_get(line, CA_PATH)
}

/// The PEM `/ca.crt` serves; `None` when decryption is off.
#[cfg(target_os = "linux")]
fn ca_pem(mitm: Option<&Mitm>) -> Option<&[u8]> {
    mitm.map(|mitm| mitm.ca().pem())
}

/// Decryption exists on Linux only, so there is no CA to serve here.
#[cfg(not(target_os = "linux"))]
fn ca_pem(_mitm: Option<&Mitm>) -> Option<&[u8]> {
    None
}

/// The PAC file for a client that reached us at `addr`. The tail `; DIRECT`
/// keeps traffic flowing when this proxy is down (fail-open).
fn pac_body(addr: SocketAddr) -> String {
    format!("{PAC_HEAD}  return \"PROXY {addr}; DIRECT\";\n}}\n")
}

/// Answers a PAC request with `200` and closes. `addr` is the local end of
/// this very connection, i.e. the address the client actually reached, which
/// stays correct when listening on `0.0.0.0`. Write failures are ignored like
/// in `respond_status`.
fn serve_pac(stream: &mut TcpStream, peer: SocketAddr) {
    let Ok(addr) = stream.local_addr() else {
        return;
    };
    let body = pac_body(addr);
    // One String, one write_all: see `respond_status`.
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::proxy_pac_served(crate::i18n::locale(), peer.ip())
    );
}

/// Answers a `/ca.crt` request with the PEM as it is and closes. No
/// `Content-Disposition`: iOS Safari only offers to install a profile when the
/// response is not an attachment. Write failures are ignored like in
/// `respond_status`.
fn serve_ca(stream: &mut TcpStream, peer: SocketAddr, pem: &[u8]) {
    // One buffer, one write_all: see `respond_status`.
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pem.len()
    )
    .into_bytes();
    response.extend_from_slice(pem);
    let _ = stream.write_all(&response);
    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::proxy_ca_served(crate::i18n::locale(), peer.ip())
    );
}

/// 固定文の HTTP 応答を1つ書いて終える。書き込み失敗（client が先に切った
/// 等）は無視する（fail-open：呼び出し元は close するだけで、処理を止める
/// 理由にしない）。
///
/// **`write!` を直接 `stream` へ渡さない。**`write!` は書式文字列の
/// 断片ごとに `Write::write_str` を呼び、`TcpStream`（無 buffer）の上では
/// 断片ごとに別々の `write()` syscall になり得る。client が最初の
/// syscall 分だけを1回の `read()` で受け取って応答が完結したと誤認する
/// （実測：`idle_client_is_timed_out_and_releases_the_connection_slot` が
/// `"HTTP/1.1 "` だけを読んで落ちた）。`format!` で1つの `String` に
/// 組み立ててから `write_all` する（1回の syscall にまとめる）。
fn respond_status(stream: &mut TcpStream, code: u16, reason: &str) {
    let response = format!("HTTP/1.1 {code} {reason}\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(response.as_bytes());
}

/// `host` を名前解決した結果を1つ返す。解決できなければ `0.0.0.0`
/// （`docs/design.md`「段階7 proxy」節：「名前解決失敗を表す既存の値が
/// 無いため、この値を割り当てる」）。
fn resolve_dst_ip(host: &str, port: u16) -> IpAddr {
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| addr.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// `SniJudge` / `IpJudge` / `AvJudge` の3つだけを、段階の番号順（sni=2,
/// iplist=5, av=6）で評価する。`CnameJudge` / `IdsJudge` は proxy に無い
/// （段階3・段階4 は proxy の対象外。`docs/design.md`「段階7 proxy」節）。
/// lock は判定の間だけ短く取る。lock が poison していたら fail-open で
/// `None`（pass）にする。
fn judge_flow(
    inputs: &Mutex<WatchInputs>,
    sni_state: &SniState,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Judged {
    let Ok(guard) = inputs.lock() else {
        return Judged::pass();
    };
    let jc = guard.judge_config();
    #[cfg(target_os = "linux")]
    let allowlisted = sni_state.sni().is_some_and(|sni| jc.allowlist.matches(sni));
    let sni_judge = SniJudge {
        blocklist: jc.blocklist,
    };
    let ip_judge = IpJudge { iplist: jc.iplist };
    let av_judge = AvJudge { av: jc.av };
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut judges: Vec<&dyn Judge> = vec![&sni_judge, &ip_judge, &av_judge];
    // Stage 10: the chain judge reads the prober's table and comes last.
    #[cfg(target_os = "linux")]
    let defense = guard.defense();
    #[cfg(target_os = "linux")]
    let stop_hit =
        |chain: &[crate::distrust::CertPrints]| defense.as_ref().is_some_and(|d| d.stop_hit(chain));
    #[cfg(target_os = "linux")]
    let chain_judge = defense.as_deref().map(|d| crate::prober::ChainJudge {
        verdicts: d.verdicts(),
        hit: &stop_hit,
    });
    #[cfg(target_os = "linux")]
    if let Some(judge) = &chain_judge {
        judges.push(judge);
    }
    let empty_qnames: HashSet<String> = HashSet::new();
    let input = JudgeInput {
        sni_state,
        cname_matched_qnames: &empty_qnames,
        dst_ip,
        dst_port,
    };
    let reason = run_judges_with_allowlist(jc.allowlist, &judges, &input);
    Judged {
        reason,
        #[cfg(target_os = "linux")]
        allowlisted,
        #[cfg(target_os = "linux")]
        defense,
    }
}

/// What the stage 7 judges said about one flow, and what stage 10 needs next.
struct Judged {
    reason: Option<Reason>,
    /// The allowlist matched, so no judge ran.
    #[cfg(target_os = "linux")]
    allowlisted: bool,
    #[cfg(target_os = "linux")]
    defense: Option<std::sync::Arc<crate::defense::Defense>>,
}

impl Judged {
    /// The verdict when the inputs cannot be read: pass (fail-open).
    fn pass() -> Self {
        Self {
            reason: None,
            #[cfg(target_os = "linux")]
            allowlisted: false,
            #[cfg(target_os = "linux")]
            defense: None,
        }
    }
}

/// The verdict after stage 10 had its say. Without stage 10 it is the stage 7
/// verdict.
#[cfg(target_os = "linux")]
fn apply_defense(judged: &Judged, key: FlowKey, host: &str) -> Option<Reason> {
    match &judged.defense {
        Some(defense) => {
            let facts = crate::defense::FlowFacts {
                key,
                host,
                allowlisted: judged.allowlisted,
            };
            defense.assess(&facts, judged.reason)
        }
        None => judged.reason,
    }
}

#[cfg(not(target_os = "linux"))]
fn apply_defense(judged: &Judged, _key: FlowKey, _host: &str) -> Option<Reason> {
    judged.reason
}

/// 1 flow 1行 を `flows.jsonl` へ書く（`docs/design.md`「段階7 proxy」節）。
/// `src_ip` / `src_port` は proxy へ繋いだ client の peer であり、上流へ出る
/// proxy 自身の port ではない。field の集合は「名前と置き場」の宣言のとおり。
/// 書き込みに失敗しても接続処理は止めない
/// （fail-open。log の失敗で proxy が機能停止しない）。Stage 8 writes its
/// `block`/`av` line through here (`mitm.rs`).
pub(crate) fn log_flow(
    log: &FlowLogSink,
    key: FlowKey,
    sni_state: &SniState,
    reason: Option<Reason>,
) {
    let (decision, reason_str) = match reason {
        Some(r) => (DECISION_BLOCK, Some(r.as_log_str())),
        None => (DECISION_PASS, None),
    };
    match FlowLogEntry::with_verdict(key, sni_state, decision, reason_str) {
        Ok(entry) => {
            if let Err(e) = log.write(&entry) {
                eprintln!("packetdeath: [error] {e}");
            }
        }
        Err(e) => {
            eprintln!(
                "packetdeath: [error] {}",
                crate::i18n::timestamp_format_failed(crate::i18n::locale(), e)
            );
        }
    }
}

/// 判定を通った flow を上流へ繋ぐ。`CONNECT` は `200` を返してから復号せず
/// 中継する。絶対 URL の平文 HTTP は request 行を相対 path へ書き換えて
/// 転送する（`docs/design.md`「段階7 proxy」節）。
fn forward(
    mut reader: BufReader<TcpStream>,
    target: RequestTarget,
    headers: &[String],
    mut upstream: TcpStream,
    pipe_idle_timeout: Duration,
) {
    match target {
        RequestTarget::Connect { .. } => {
            if reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
        }
        RequestTarget::Absolute {
            method,
            path,
            version,
            ..
        } => {
            let mut request = format!("{method} {path} {version}\r\n");
            for header in headers {
                let is_connection_header = header
                    .split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"));
                if is_connection_header {
                    continue;
                }
                request.push_str(header);
                request.push_str("\r\n");
            }
            request.push_str("Connection: close\r\n\r\n");
            if upstream.write_all(request.as_bytes()).is_err() {
                return;
            }
        }
    }

    // BufReader が既に読み込み済みの byte（header の直後に client が続けて
    // 送っていた TLS ClientHello や HTTP body）を、raw pipe を始める前に
    // 上流へ転送する。`BufReader::into_inner` は内部 buffer を捨てるので、
    // 先に `buffer()` で取り出しておく。
    let leftover = reader.buffer().to_vec();
    let client = reader.into_inner();

    // request 行を待つ `request_read_timeout` から、中継の無通信を許す
    // `pipe_idle_timeout` へ切り替える。read/write の両方に置く（read だけ
    // では、上流や client の受信側が詰まって write が永久に戻らない経路を
    // 塞げない）。詰まった接続を切る以外の意味は持たない（fail-open の判定は
    // 変えない）。設定に失敗する socket（既に close 済み等）は、この時点で
    // 諦めて閉じる。
    if client.set_read_timeout(Some(pipe_idle_timeout)).is_err() {
        return;
    }
    if client.set_write_timeout(Some(pipe_idle_timeout)).is_err() {
        return;
    }
    if upstream.set_read_timeout(Some(pipe_idle_timeout)).is_err() {
        return;
    }
    if upstream.set_write_timeout(Some(pipe_idle_timeout)).is_err() {
        return;
    }

    if !leftover.is_empty() && upstream.write_all(&leftover).is_err() {
        return;
    }
    pipe_bidirectional(client, upstream);
}

/// 復号しない双方向中継。2 thread で copy し、片方が閉じたら もう片方の
/// 書き込み側を shutdown して終わらせる（`docs/design.md`「段階7 proxy」節）。
/// 呼び出し側（`forward`）が両 stream に `pipe_idle_timeout` を設定済みで
/// あることが前提。無通信のまま timeout すると `io::copy` の読み込みが
/// `Err`（`WouldBlock`/`TimedOut`）を返して即 戻るので、下の `let _ =
/// io::copy(...)` がそのまま shutdown へ抜ける（片方が正常に閉じた場合と
/// 同じ経路）。
fn pipe_bidirectional(client: TcpStream, upstream: TcpStream) {
    let (client_read, mut client_write) = match client.try_clone() {
        Ok(c) => (c, client),
        Err(_) => return,
    };
    let (mut upstream_read, upstream_write) = match upstream.try_clone() {
        Ok(u) => (upstream, u),
        Err(_) => return,
    };

    let uploader = thread::spawn(move || {
        let mut client_read = client_read;
        let mut upstream_write = upstream_write;
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = uploader.join();
}

/// block 判定かつ `DenyMode::Blackhole` のとき、繋がったふりをして
/// （`200 Connection Established` を返して）以後 client から届く byte を
/// 読んで捨て、何も送り返さない。上流へは1 byte も出さない（TCP を張らない）。
/// No fake response either: stage 7 does not break TLS, so it could not forge
/// one the client would trust. `hold` 経過か client の EOF で戻る。
/// `hold` は read のたびに残り時間へ詰め直す ── client が細切れに byte を
/// 送り続けても、合計の hold 時間を超えて黙り続けない（「時間無制限に黙る」
/// を採らないため）。
fn run_blackhole(reader: &mut BufReader<TcpStream>, host: &str, hold: Duration) {
    eprintln!(
        "packetdeath: [debug] {}",
        crate::i18n::proxy_blackhole_entered(crate::i18n::locale(), host, hold.as_secs())
    );
    if reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    let deadline = Instant::now() + hold;
    let mut buf = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if reader.get_mut().set_read_timeout(Some(remaining)).is_err() {
            break;
        }
        match reader.read(&mut buf) {
            Ok(0) => break,    // client が EOF（Shutdown::Write 相当）
            Ok(_) => continue, // 読んで捨てる。何も送り返さない
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break; // hold 経過
            }
            Err(_) => break,
        }
    }
}

/// `handle_connection` が `active`（一般枠）をどう扱ったか。
/// `MovedToBlackhole` は、block 判定かつ `DenyMode::Blackhole` の経路で
/// `handle_connection` 自身が `active.fetch_sub` を打ち済みであることを表す
/// （blackhole 枠が満杯で結局 403 に倒れた場合も含む ── どちらの分岐でも
/// 一般枠は既に解放済みのため）。serve 側の二重解放を防ぐ。
enum SlotOutcome {
    /// `active` の枠のまま終わった。serve 側が `active.fetch_sub` を打つ。
    General,
    /// `active` を `handle_connection` の中で既に解放した。serve 側は
    /// `active.fetch_sub` を打たない。
    MovedToBlackhole,
}

/// Stage 8 conditions 3 to 6 of "復号する範囲" (1 is `mitm` being `Some`, 2 is
/// the stage 7 judgement having passed): not allowlisted, on `--mitm-list`,
/// the decrypt port with a name rather than an IP literal, and the (client IP,
/// host) pair not bypassed.
#[cfg(target_os = "linux")]
fn decrypts(
    inputs: &Mutex<WatchInputs>,
    mitm: &Mitm,
    client_ip: IpAddr,
    host: &str,
    port: u16,
) -> bool {
    if port != mitm.decrypt_port() || host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let Ok(guard) = inputs.lock() else {
        return false;
    };
    let listed = guard.mitm_target(host);
    drop(guard);
    listed && !mitm.is_bypassed(client_ip, host, Instant::now())
}

/// What became of a CONNECT handed to stage 8.
#[cfg(target_os = "linux")]
enum Decrypted {
    /// Tunnel it as stage 7 does: the client and an upstream connection.
    Tunnel(BufReader<TcpStream>, TcpStream),
    /// Stage 8 handled the connection and closed it.
    Handled,
    /// Stage 10 denied the upstream chain. The client was sent nothing yet.
    Denied(BufReader<TcpStream>),
}

/// Hands a CONNECT that meets every condition to stage 8.
#[cfg(target_os = "linux")]
fn try_decrypt(
    mitm: Option<&Mitm>,
    reader: BufReader<TcpStream>,
    upstream: TcpStream,
    flow: crate::mitm::FlowContext<'_>,
    inputs: &Mutex<WatchInputs>,
) -> Decrypted {
    let Some(mitm) = mitm else {
        return Decrypted::Tunnel(reader, upstream);
    };
    if !decrypts(inputs, mitm, flow.key.src_ip, flow.host, flow.key.dst_port) {
        return Decrypted::Tunnel(reader, upstream);
    }
    match mitm.intercept(reader, upstream, &flow) {
        crate::mitm::Outcome::Done => Decrypted::Handled,
        crate::mitm::Outcome::Denied { reader } => Decrypted::Denied(reader),
        crate::mitm::Outcome::Fallback {
            reader,
            upstream: Some(upstream),
        } => Decrypted::Tunnel(reader, upstream),
        crate::mitm::Outcome::Fallback {
            mut reader,
            upstream: None,
        } => {
            // The first connection went into the failed handshake.
            let addr = SocketAddr::new(flow.key.dst_ip, flow.key.dst_port);
            match TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT) {
                Ok(upstream) => Decrypted::Tunnel(reader, upstream),
                Err(_) => {
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::proxy_upstream_unreachable(
                            crate::i18n::locale(),
                            flow.host,
                            flow.key.dst_port
                        )
                    );
                    respond_status(reader.get_mut(), 502, "Bad Gateway");
                    Decrypted::Handled
                }
            }
        }
    }
}

/// Arms the read and the write timeout of a fresh client socket with the same
/// value: the read side bounds the wait for the request line, the write side
/// bounds the first response. `false` when either could not be set.
fn arm_request_timeouts(client: &TcpStream, timeout: Duration) -> bool {
    client.set_read_timeout(Some(timeout)).is_ok()
        && client.set_write_timeout(Some(timeout)).is_ok()
}

/// How long to wait after a failed `accept()`.
fn accept_failure_backoff() -> Duration {
    ACCEPT_RETRY_DELAY
}

/// Answers a denied flow in the form `--deny` names, and says how the slot of
/// `active` was handled.
fn deny_connection(
    mut reader: BufReader<TcpStream>,
    host: &str,
    limits: ProxyLimits,
    active: &AtomicUsize,
    blackhole_active: &AtomicUsize,
) -> SlotOutcome {
    match limits.deny {
        DenyMode::Forbid => {
            // 上流へ1 byte も出さない（TCP connect の前で折り返す。
            // `docs/design.md`「段階7 proxy」節）。
            respond_status(reader.get_mut(), 403, "Forbidden");
            SlotOutcome::General
        }
        DenyMode::Blackhole => {
            // 一般枠を解放してから blackhole 枠を取る。以後どちらの分岐でも一般枠は解放済みなので
            // `MovedToBlackhole` を返す（serve 側の二重解放を防ぐ）。
            active.fetch_sub(1, Ordering::AcqRel);
            let claimed =
                blackhole_active.fetch_add(1, Ordering::AcqRel) < limits.max_blackhole_connections;
            if !claimed {
                // 満杯なら黙らず即 403 に倒す（時間無制限に黙らない）。
                blackhole_active.fetch_sub(1, Ordering::AcqRel);
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::proxy_blackhole_limit_reached(
                        crate::i18n::locale(),
                        limits.max_blackhole_connections
                    )
                );
                respond_status(reader.get_mut(), 403, "Forbidden");
                return SlotOutcome::MovedToBlackhole;
            }
            run_blackhole(&mut reader, host, limits.blackhole_hold);
            blackhole_active.fetch_sub(1, Ordering::AcqRel);
            SlotOutcome::MovedToBlackhole
        }
    }
}

/// 1接続分の処理。判定 → log → （通れば）上流へ接続して中継する。
/// A passed CONNECT may be decrypted by stage 8 (`mitm`) instead of tunnelled.
fn handle_connection(
    client: TcpStream,
    inputs: &Mutex<WatchInputs>,
    log: &FlowLogSink,
    limits: ProxyLimits,
    active: &AtomicUsize,
    blackhole_active: &AtomicUsize,
    mitm: Option<&Mitm>,
) -> SlotOutcome {
    let Ok(peer) = client.peer_addr() else {
        return SlotOutcome::General;
    };
    // A client that never sends a request line, or never reads the first
    // response, must not hold a thread and an `active` slot forever. A socket
    // that cannot take the timeouts (very rare) is dropped here.
    if !arm_request_timeouts(&client, limits.request_read_timeout) {
        return SlotOutcome::General;
    }
    let mut reader = BufReader::new(client);

    let Some((target, headers)) = read_request(&mut reader, peer, mitm) else {
        return SlotOutcome::General;
    };

    let host = target.host().to_string();
    let port = target.port();
    let dst_ip = resolve_dst_ip(&host, port);
    let key = FlowKey {
        proto: Proto::Tcp,
        src_ip: peer.ip(),
        src_port: peer.port(),
        dst_ip,
        dst_port: port,
    };
    let sni_state = SniState::Ok(host.clone());

    let judged = judge_flow(inputs, &sni_state, dst_ip, port);
    let reason = apply_defense(&judged, key, &host);
    log_flow(log, key, &sni_state, reason);

    if reason.is_some() {
        return deny_connection(reader, &host, limits, active, blackhole_active);
    }

    if dst_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
        eprintln!(
            "packetdeath: [warn] {}",
            crate::i18n::proxy_upstream_unreachable(crate::i18n::locale(), &host, port)
        );
        respond_status(reader.get_mut(), 502, "Bad Gateway");
        return SlotOutcome::General;
    }

    let upstream_addr = SocketAddr::new(dst_ip, port);
    let upstream = match TcpStream::connect_timeout(&upstream_addr, UPSTREAM_CONNECT_TIMEOUT) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "packetdeath: [warn] {}",
                crate::i18n::proxy_upstream_unreachable(crate::i18n::locale(), &host, port)
            );
            respond_status(reader.get_mut(), 502, "Bad Gateway");
            return SlotOutcome::General;
        }
    };

    #[cfg(target_os = "linux")]
    let (reader, upstream) = match target {
        RequestTarget::Connect { .. } => {
            let flow = crate::mitm::FlowContext {
                key,
                host: &host,
                sni_state: &sni_state,
                log,
                limits,
                defense: judged.defense.as_deref(),
            };
            match try_decrypt(mitm, reader, upstream, flow, inputs) {
                Decrypted::Tunnel(reader, upstream) => (reader, upstream),
                Decrypted::Handled => return SlotOutcome::General,
                Decrypted::Denied(reader) => {
                    // The pass row above stays; this row says what happened
                    // after the upstream handshake, like the `av` block row.
                    log_flow(log, key, &sni_state, Some(Reason::Chain));
                    return deny_connection(reader, &host, limits, active, blackhole_active);
                }
            }
        }
        RequestTarget::Absolute { .. } => (reader, upstream),
    };
    #[cfg(not(target_os = "linux"))]
    let _ = mitm;

    forward(reader, target, &headers, upstream, limits.pipe_idle_timeout);
    SlotOutcome::General
}

/// bind 済みの `listener` で accept loop を回す。呼び出し元が止めるまで
/// 戻らない（他の `run_*` loop と同じ形。Ctrl-C の既定動作に乗る）。
///
/// `inputs` は `RELOAD_POLL_INTERVAL` ごとに読み直す。接続ごとに
/// `std::thread::scope` で thread を切り、`inputs` を `Mutex` 越しに共有する
/// （`docs/design.md`「段階7 proxy」節：「reload：`block_loop::WatchInputs`
/// を Arc<Mutex<_>> で共有し」。`Arc` の代わりに `thread::scope` を使うのは、
/// `WatchInputs<'a>` が `iplist` / `av` への借用を持ち、`'static` を要求する
/// `Arc<Mutex<_>>` + `thread::spawn` の組より、scope 付き thread の方が
/// 素直に借用を通せるため。挙動は同じ）。
///
/// `limits` は request 行を待つ timeout・中継の無通信 timeout・同時接続数の
/// 上限をまとめた設定（`ProxyLimits`）。既定値は `ProxyLimits::default()`。
/// test は本番値（30秒・300秒・256本）を待つと遅くなるため、明示的に短い
/// 値を渡す。
///
/// `mitm` is stage 8's state when decryption is enabled, `None` otherwise
/// (stage 7 behaviour; always `None` off Linux).
pub fn serve(
    listener: TcpListener,
    allow_from: &AllowFrom,
    log: &FlowLogSink,
    inputs: WatchInputs,
    limits: ProxyLimits,
    mitm: Option<&Mitm>,
) {
    let locale = crate::i18n::locale();
    let listen_desc = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    eprintln!(
        "packetdeath: [info] {}",
        crate::i18n::proxy_started(locale, listen_desc)
    );

    let inputs = Mutex::new(inputs);
    let active = AtomicUsize::new(0);
    let blackhole_active = AtomicUsize::new(0);
    let mut last_poll = Instant::now();

    thread::scope(|scope| {
        for incoming in listener.incoming() {
            let now = Instant::now();
            if now.duration_since(last_poll) >= RELOAD_POLL_INTERVAL {
                last_poll = now;
                if let Ok(mut guard) = inputs.lock() {
                    guard.poll_reloads();
                }
            }

            let stream = match incoming {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::proxy_accept_failed(locale, &e)
                    );
                    thread::sleep(accept_failure_backoff());
                    continue;
                }
            };
            let peer = match stream.peer_addr() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !allow_from.contains(peer.ip()) {
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::proxy_connection_rejected(locale, peer.ip())
                );
                continue;
            }

            if active.fetch_add(1, Ordering::AcqRel) >= limits.max_concurrent_connections {
                active.fetch_sub(1, Ordering::AcqRel);
                eprintln!(
                    "packetdeath: [warn] {}",
                    crate::i18n::proxy_connection_limit_reached(
                        locale,
                        limits.max_concurrent_connections
                    )
                );
                let mut stream = stream;
                respond_status(&mut stream, 503, "Service Unavailable");
                continue;
            }

            let inputs = &inputs;
            let active = &active;
            let blackhole_active = &blackhole_active;
            scope.spawn(move || {
                // `MovedToBlackhole` のときは `handle_connection` の中で
                // 既に `active.fetch_sub` を打ち済み
                // （二重解放を防ぐ）。
                if let SlotOutcome::General =
                    handle_connection(stream, inputs, log, limits, active, blackhole_active, mitm)
                {
                    active.fetch_sub(1, Ordering::AcqRel);
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::Allowlist;
    use crate::av::AvList;
    use crate::blocklist::Blocklist;
    use crate::flow::FlowLogSink;
    use crate::iplist::IpList;
    use std::io::Cursor;
    use std::net::Ipv6Addr;
    use std::sync::mpsc;

    // ------------------------------------------------------------
    // request 行の parse（テスト項目1）
    // ------------------------------------------------------------

    #[test]
    fn parses_connect_target() -> Result<(), String> {
        // test でも panic!/unwrap/expect を避け、`Result<(), String>` を
        // 返して `?` で伝播する。
        let target = parse_request_line("CONNECT example.org:443 HTTP/1.1");
        let Some(RequestTarget::Connect { host, port }) = target else {
            return Err("CONNECT を parse できなかった".to_string());
        };
        assert_eq!(host, "example.org");
        assert_eq!(port, 443);
        Ok(())
    }

    #[test]
    fn parses_connect_target_with_ipv6_literal() -> Result<(), String> {
        let target = parse_request_line("CONNECT [::1]:443 HTTP/1.1");
        let Some(RequestTarget::Connect { host, port }) = target else {
            return Err("IPv6 literal の CONNECT を parse できなかった".to_string());
        };
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
        Ok(())
    }

    #[test]
    fn parses_absolute_url_with_path() -> Result<(), String> {
        let target = parse_request_line("GET http://example.org/ads.js HTTP/1.1");
        let Some(RequestTarget::Absolute {
            method,
            host,
            port,
            path,
            version,
        }) = target
        else {
            return Err("絶対 URL を parse できなかった".to_string());
        };
        assert_eq!(method, "GET");
        assert_eq!(host, "example.org");
        assert_eq!(port, 80);
        assert_eq!(path, "/ads.js");
        assert_eq!(version, "HTTP/1.1");
        Ok(())
    }

    #[test]
    fn parses_absolute_url_without_path_defaults_to_root() -> Result<(), String> {
        let target = parse_request_line("GET http://example.org HTTP/1.1");
        let Some(RequestTarget::Absolute { path, .. }) = target else {
            return Err("path 省略の絶対 URL を parse できなかった".to_string());
        };
        assert_eq!(path, "/");
        Ok(())
    }

    #[test]
    fn relative_path_request_is_rejected() {
        // どちらでもない（CONNECT でも絶対 URL でもない）request は 400 へ倒す。
        assert!(parse_request_line("GET /ads.js HTTP/1.1").is_none());
    }

    #[test]
    fn garbage_line_is_rejected() {
        assert!(parse_request_line("not an http request").is_none());
        assert!(parse_request_line("").is_none());
    }

    #[test]
    fn oversized_line_without_newline_is_too_long() {
        // テスト項目1：8 KiB 超は 400 へ倒す入口（`read_capped_line` の契約）。
        let huge = "x".repeat(MAX_LINE_BYTES + 100);
        let mut cursor = Cursor::new(huge.into_bytes());
        assert!(matches!(
            read_capped_line(&mut cursor),
            LineOutcome::TooLong
        ));
    }

    #[test]
    fn line_within_limit_is_read() -> Result<(), String> {
        let mut cursor = Cursor::new(b"CONNECT example.org:443 HTTP/1.1\r\n".to_vec());
        match read_capped_line(&mut cursor) {
            LineOutcome::Line(line) => {
                assert_eq!(line, "CONNECT example.org:443 HTTP/1.1");
                Ok(())
            }
            _ => Err("Line を期待した".to_string()),
        }
    }

    #[test]
    fn empty_input_is_eof() {
        let mut cursor = Cursor::new(Vec::new());
        assert!(matches!(read_capped_line(&mut cursor), LineOutcome::Eof));
    }

    // ------------------------------------------------------------
    // allow-from の既定と CIDR 判定（テスト項目2）
    // ------------------------------------------------------------

    #[test]
    fn default_allow_from_accepts_loopback_and_rfc1918() {
        let allow = AllowFrom::default_private();
        assert!(allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))));
        assert!(allow.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3))));
        assert!(allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(172, 20, 0, 1))));
        assert!(allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn default_allow_from_rejects_public_address() {
        let allow = AllowFrom::default_private();
        assert!(!allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn configured_allow_from_accepts_only_given_cidr() {
        let allow = AllowFrom::from_args(&["203.0.113.0/24".to_string()]);
        assert!(allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5))));
        // 明示的に渡したので、既定（loopback）へは倒れない。
        assert!(!allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn configured_allow_from_with_only_invalid_entries_denies_everyone() {
        // 既定へこっそり倒れると open proxy 対策が弱まるので、deny-all のまま。
        let allow = AllowFrom::from_args(&["not-a-cidr".to_string()]);
        assert!(!allow.contains(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))));
    }

    // ------------------------------------------------------------
    // 403 時に上流へ出ないこと（テスト項目3）
    // ------------------------------------------------------------

    #[test]
    fn blocked_connect_makes_zero_upstream_connections() -> Result<(), String> {
        let fake_upstream =
            std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let upstream_port = fake_upstream
            .local_addr()
            .map_err(|e| e.to_string())?
            .port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(fake_upstream.accept().is_ok());
        });

        let proxy_listener =
            std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let proxy_addr = proxy_listener.local_addr().map_err(|e| e.to_string())?;
        let mut client = TcpStream::connect(proxy_addr).map_err(|e| e.to_string())?;
        let (server_side, _) = proxy_listener.accept().map_err(|e| e.to_string())?;

        let blocklist = Blocklist::parse("127.0.0.1\n");
        let allowlist = Allowlist::empty();
        let av = AvList::empty();
        let inputs = WatchInputs::new(blocklist, allowlist, None, IpList::empty(), &av);
        let inputs = Mutex::new(inputs);

        let dir =
            std::env::temp_dir().join(format!("packetdeath-proxy-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let log = FlowLogSink::open(&dir.join("flows.jsonl")).map_err(|e| e.to_string())?;

        write!(
            client,
            "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
        )
        .map_err(|e| e.to_string())?;

        // `deny` を明示的に `Forbid` にする ── 既存の 403 前提を消さない
        // （既定は `Blackhole` のため）。
        let limits = ProxyLimits {
            deny: DenyMode::Forbid,
            ..ProxyLimits::default()
        };
        let active = AtomicUsize::new(1);
        let blackhole_active = AtomicUsize::new(0);
        handle_connection(
            server_side,
            &inputs,
            &log,
            limits,
            &active,
            &blackhole_active,
            None,
        );

        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .map_err(|e| e.to_string())?;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "403 を返していない: {response:?}"
        );

        let accepted = rx.recv_timeout(Duration::from_millis(300));
        assert!(
            accepted.is_err(),
            "blocklist に当たったのに上流へ接続が届いた"
        );
        Ok(())
    }

    // ------------------------------------------------------------
    // `--deny` の parse（テスト項目4）
    // ------------------------------------------------------------

    #[test]
    fn deny_mode_parses_blackhole_and_403() -> Result<(), String> {
        if "blackhole".parse::<DenyMode>() != Ok(DenyMode::Blackhole) {
            return Err("\"blackhole\" が DenyMode::Blackhole へ parse できなかった".to_string());
        }
        if "403".parse::<DenyMode>() != Ok(DenyMode::Forbid) {
            return Err("\"403\" が DenyMode::Forbid へ parse できなかった".to_string());
        }
        Ok(())
    }

    #[test]
    fn deny_mode_rejects_unknown_value() {
        assert!("blackhole ".parse::<DenyMode>().is_err()); // 余白付きも拒否
        assert!("Blackhole".parse::<DenyMode>().is_err()); // 大文字小文字を区別する
        assert!("forbid".parse::<DenyMode>().is_err());
        assert!("".parse::<DenyMode>().is_err());
    }

    // ------------------------------------------------------------
    // PAC（PK-78）
    // ------------------------------------------------------------

    #[test]
    fn pac_body_names_the_address_the_client_reached() {
        let addr = SocketAddr::from(([192, 0, 2, 7], 8081));
        let body = pac_body(addr);
        assert!(body.contains("return \"PROXY 192.0.2.7:8081; DIRECT\";"));
        assert!(body.starts_with("function FindProxyForURL(url, host) {"));
        assert!(body.ends_with("}\n"));
    }

    #[test]
    fn pac_body_sends_local_names_and_private_ranges_direct() {
        let body = pac_body(SocketAddr::from(([127, 0, 0, 1], 8899)));
        for needle in [
            "isPlainHostName(host)",
            "\"*.local\"",
            "\"*.lan\"",
            "\"*.home\"",
            "a === 10",
            "a === 127",
            "a === 172 && b >= 16 && b <= 31",
            "a === 192 && b === 168",
            "a === 169 && b === 254",
        ] {
            assert!(body.contains(needle), "{needle}");
        }
        assert!(!body.contains("dnsResolve"));
    }

    #[test]
    fn only_get_proxy_pac_is_a_pac_request() {
        assert!(is_pac_request("GET /proxy.pac HTTP/1.1"));
        assert!(is_pac_request("GET /proxy.pac HTTP/1.0"));
        assert!(!is_pac_request("GET /other HTTP/1.1"));
        assert!(!is_pac_request("GET /proxy.pac?x=1 HTTP/1.1"));
        assert!(!is_pac_request("POST /proxy.pac HTTP/1.1"));
        assert!(!is_pac_request("GET /proxy.pac"));
        assert!(!is_pac_request("GET /proxy.pac HTTP/1.1 extra"));
        assert!(!is_pac_request("GET http://example.org/proxy.pac HTTP/1.1"));
        assert!(!is_pac_request(""));
    }

    #[test]
    fn only_get_ca_crt_is_a_ca_request() {
        assert!(is_ca_request("GET /ca.crt HTTP/1.1"));
        assert!(is_ca_request("GET /ca.crt HTTP/1.0"));
        assert!(!is_ca_request("GET /ca.crt?x=1 HTTP/1.1"));
        assert!(!is_ca_request("POST /ca.crt HTTP/1.1"));
        assert!(!is_ca_request("GET /ca.key HTTP/1.1"));
    }

    #[test]
    fn accept_failure_backoff_is_short_and_nonzero() {
        let delay = accept_failure_backoff();
        assert!(delay >= Duration::from_millis(50), "{delay:?}");
        assert!(delay < Duration::from_secs(1), "{delay:?}");
    }

    #[test]
    fn client_timeouts_are_armed_before_the_first_response() -> Result<(), io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let _client = TcpStream::connect(listener.local_addr()?)?;
        let (server_side, _) = listener.accept()?;
        let timeout = Duration::from_secs(7);
        assert!(arm_request_timeouts(&server_side, timeout));
        assert_eq!(server_side.read_timeout()?, Some(timeout));
        assert_eq!(server_side.write_timeout()?, Some(timeout));
        Ok(())
    }
}
