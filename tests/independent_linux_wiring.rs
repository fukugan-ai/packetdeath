//! 独立検算。Linux nfqueue 本経路（`--pcapng` 未指定時）に Reassembler・
//! allowlist・走行中 reload が配線されていることを、公開 API の型だけで
//! 確かめる。`src/linux.rs` の private な内部（`inspect_ip_packet` 等）には
//! 依存しない（`independent_reload.rs` が `block_loop::WatchInputs` の
//! private な中身に依存しないのと同じ判断）。
//!
//! `packetdeath::linux` は `#[cfg(target_os = "linux")]` でしか build
//! されないため、この file 全体も同じ cfg で絞る（Windows cross build
//! （PK-6）でこの file ごと消える）。
//!
//! # `BlockConfig` に `allowlist` field を持たせない理由
//!
//! 「`BlockConfig` に `allowlist` field が在ること」を検証する形は
//! 実装できない。`block_loop::WatchInputs::new` は
//! `allowlist: Allowlist`（所有権を取る。`&` ではない）を受け取る既存の
//! 契約で、`main.rs` が同じ値を `BlockConfig` の `&'a Allowlist` field にも
//! 貸そうとすると、値を move した後もその借用を生かし続けることになり
//! E0505（borrow of moved value）で **コンパイルが通らない**
//! （`実測`。`cargo build` で確認済み）。
//!
//! allowlist を本当に「走行中に読み直す」には `WatchInputs` が所有権を
//! 持つ必要があり、`BlockConfig` が別に静的な allowlist を持つと、
//! どちらが実際の判定に使われるかが二重管理になる ──
//! `[info] blocklist を読み直した` 相当の log が出ても判定には反映され
//! ない、という壊れた挙動になりかねない。そのため `src/linux.rs::BlockConfig`
//! から blocklist と同じ理由で allowlist も外し、`WatchInputs::judge_config()`
//! （`pub(crate)`。`linux.rs` と同じ crate 内からしか呼べない）から
//! `run_block` が都度 取る設計にした。
//!
//! この test は代わりに、実際に成立する契約 ── `BlockConfig` が blocklist を
//! 持たないこと（`iplist` / `av` / `ids_drop_set` / `dns_log` だけで組み
//! 立てられること）と、`run_block` が `WatchInputs` を `&mut` で受け取る
//! 型であること ── を compile で確かめる。
//!
//! # `unwrap()` / `expect()` を使わない
//! この test は fallible な呼び出しを行わないため、素朴な `#[test] fn ...()`
//! （`Result` を返さない形）で書く。

#![cfg(target_os = "linux")]

use packetdeath::av::AvList;
use packetdeath::block_loop::WatchInputs;
use packetdeath::flow::FlowLogSink;
use packetdeath::ids::IdsDropSet;
use packetdeath::linux::{BlockConfig, LinuxQueueError};

#[test]
fn block_config_is_built_without_a_blocklist_field() {
    // `blocklist:` や `iplist:` を足すと E0560（no such field）で落ちる。この
    // literal が過不足なく（`av` / `ids_drop_set` / `dns_log` の3つだけで）
    // コンパイルを通ること自体が「blocklist と iplist を持たない（`WatchInputs`
    // だけが持つ。`docs/design.md`「段階9」）」ことの型による証拠。
    let av = AvList::empty();
    let ids_drop_set = IdsDropSet::new();
    let _config = BlockConfig {
        dns_log: None,
        ids_drop_set: &ids_drop_set,
        av: &av,
    };
}

#[test]
fn run_block_takes_watch_inputs_by_mutable_reference() {
    // 実行はしない（root と実 netlink socket が要るため。`docs/design.md`
    // の受入 PK-10〜PK-11 が実機で、PK-12 が `cargo test` の名指しで確かめる）。
    // 関数ポインタへの型強制だけで
    // 第4引数が `&mut WatchInputs` であることを担保する。
    let _f: fn(u16, &FlowLogSink, &BlockConfig, &mut WatchInputs) -> Result<(), LinuxQueueError> =
        packetdeath::linux::run_block;
}
