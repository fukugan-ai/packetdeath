#![forbid(unsafe_code)]

//! packetdeath 段階1〜4（Linux / nfqueue）。`docs/design.md` が正本。
//!
//! 段階1「観測」：TLS ClientHello の SNI（平文）と宛先を見て、1 flow 1行で
//! `flows.jsonl` に出す。遮断はしない。
//! 段階2「遮断」：blocklist に当たる SNI の flow を落とす。
//! 段階3「CNAME チェーン解決」：DNS 応答の CNAME チェーンが blocklist に当たる
//! flow を落とす。
//! 段階4「IPS 化」：Suricata の `eve.json` の alert を読み、`--ips-sids` に
//! 当たる宛先を落とす（`ids.rs`）。

pub mod allowlist;
pub mod av;
pub mod blocklist;
pub mod dns;
pub mod eval;
pub mod filterlist;
pub mod flow;
pub mod i18n;
pub mod ids;
pub mod iplist;
pub mod judge;
pub mod proxy;
pub mod reassemble;
pub mod reload;
pub mod sni;
pub mod waf;

#[cfg(target_os = "linux")]
pub mod linux;

// Stage 8 (MITM). The TLS crates are Linux-only dependencies (`Cargo.toml`),
// so the four modules that use them are Linux-only too. `docs/design.md`
// "段階8 MITM" names exactly these four.
#[cfg(target_os = "linux")]
pub mod ca;
#[cfg(target_os = "linux")]
pub mod clamd;
// Stage 10 (active defense). `docs/design.md` "段階10 能動防御". Linux only for
// the same reason: it reads certificates with the Linux-only TLS crates.
#[cfg(target_os = "linux")]
pub mod defense;
#[cfg(target_os = "linux")]
pub mod distrust;
#[cfg(target_os = "linux")]
pub mod mitm;
#[cfg(target_os = "linux")]
pub mod prober;
#[cfg(target_os = "linux")]
pub mod scan;

// `windows.rs` の中身（pcapng の parse、SNI 判定への橋渡し、`MIB_TCPROW` 相当の
// byte order 構築）は OS 非依存の byte 列処理であり、pktmon の起動や
// `SetTcpEntry` の呼び出しは持たない（`SAFETY` を要する箇所は実装していない。
// `src/windows.rs` 冒頭のコメントが正本）。したがって Linux 側の `cargo test`
// でも PW-0〜PW-3 を検証できるよう、`target_os` で絞らずに常に build する。
pub mod windows;

// `ps_bridge.rs` も同じ理由（`windows.rs` 冒頭コメントが正本の判断）で
// `target_os` を絞らない。`powershell.exe` の起動は Windows でしか成功しないが、
// 行の組み立て・parse・子 process の生死検知・timeout 処理は OS 非依存の
// byte/文字列処理であり、Linux 側の `cargo test` でも PS-0〜PS-4 を
// 検証できるようにする。
pub mod ps_bridge;

// `block_loop.rs` は「pcapng を読む→SNI 判定→PsBridge で切る」loop の中身を
// OS に依存しない形へ切り出した module（Linux の `cargo test` で
// PI-0〜PI-4 が走る）。file I/O と `PsBridge` の spawn は Windows でしか意味を持たないが、
// byte 列の判定ロジック自体は `windows.rs` / `ps_bridge.rs` と同じ理由で
// `target_os` を絞らない。
pub mod block_loop;

// `win_service.rs` は `windows_service` crate（`Cargo.toml` で
// `[target.'cfg(windows)'.dependencies]` に限定）に依存し、Windows target
// でしか build できない。`main.rs` 側の呼び出し（`run_service_install` 等）も
// 同じく `#[cfg(windows)]` で分けている。
#[cfg(windows)]
pub mod win_service;
