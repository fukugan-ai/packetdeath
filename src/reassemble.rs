//! TCP payload を `FlowKey` 単位でつなぎ直し、複数 segment に割れた
//! ClientHello から SNI を取り出す。
//!
//! # 背景（実測）
//!
//! Windows 実機の `flows.jsonl`（1498行）で `sni_state":"fragmented"` が
//! 443 宛て行の 73.8%（559/757）を占めた。実際の pcapng を parse すると、
//! ClientHello を含む18 packet のうち15件（83%）が複数 TCP segment に
//! 割れていた。原因は耐量子鍵交換（X25519MLKEM768）の公開鍵が ClientHello
//! に約1200 byte 乗り、宣言長が 2139〜2301 byte の山を作るためで、1 TCP
//! segment（約1460 byte）に収まらない。`docs/design.md`「段階1〜4 は
//! segment を組み立て直さない」は据え置きつつ、この module だけが例外的に
//! 同じ接続の payload をつないでから `sni::extract_sni` へ渡す。
//!
//! # 守る境界
//!
//! - **1接続あたりの上限**：[`MAX_BUFFERED_BYTES`]（16 KiB）。超えたら諦めて
//!   `Fragmented` を確定する。溜め続けるとメモリが尽きるため。
//! - **溜めている接続数の上限**：[`MAX_TRACKED_FLOWS`]（4096）。超えたら
//!   最も古い接続から黙って捨てる（`[warn]` を出す。そのflowが後で新しい
//!   segment を送ってきても、また最初から組み立て直すだけで実害はない）。
//! - **payload の寿命**：[`FLOW_TTL`]（30秒）。ClientHello は接続の最初に
//!   来るので、それ以上 待つ意味が無い。`expire_stale` が定期的に払い出す。
//! - **`SniState` の3値・`flows.jsonl` の field を増やさない**。この module は
//!   `sni_state` を計算する内部の積み上げ器であり、外へ見せる形は変えない。
//! - **fail-open**：組み立てに失敗しても `Fragmented` を返すだけで、呼び出し
//!   側は素通しへ倒す（`block_loop.rs` 側の既存契約）。

use crate::flow::FlowKey;
use crate::sni::{extract_sni, SniState};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 1接続あたりに溜める TCP payload の上限（byte）。実測の宣言長の山
//  （最大 2301 byte）に対し十分な余裕を持たせる。
const MAX_BUFFERED_BYTES: usize = 16 * 1024;
/// 同時に溜めておける接続数の上限。
const MAX_TRACKED_FLOWS: usize = 4096;
/// バッファの寿命。
const FLOW_TTL: Duration = Duration::from_secs(30);

/// `Reassembler::feed` の結果。
#[derive(Debug, PartialEq, Eq)]
pub enum FrameOutcome {
    /// SNI 判定が確定した（`Ok` / `None` / 諦めて `Fragmented` の3つとも
    /// ここに含む）。呼び出し側はこれを1 flow 1行の log として書いてよい。
    Final(SniState),
    /// まだ判定できない。次の segment を待つ（log には書かない）。
    Pending,
}

/// 溜めている最中の1接続分。
struct PendingFlow {
    /// 最初に受け取った segment の TCP seq 番号。以後はこれを基準にした
    /// 相対オフセットで連結する。
    base_seq: u32,
    /// `base_seq` から連続して受け取れた byte 列。
    data: Vec<u8>,
    last_seen: Instant,
}

/// `seq` が `expected` よりどれだけ進んでいるかを、32bit 循環を考慮した
/// 符号付き差で返す。TCP seq は wraparound するため、単純な `<` 比較は使わない。
fn seq_diff(seq: u32, expected: u32) -> i64 {
    i64::from(seq.wrapping_sub(expected) as i32)
}

/// `FlowKey` 単位で TCP payload をつなぎ直す積み上げ器。
pub struct Reassembler {
    flows: HashMap<FlowKey, PendingFlow>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// `key` の接続に1 segment（`seq`、`payload`）を積む。
    ///
    /// まず単体で判定できるか試す（大多数の ClientHello は1 packet に
    /// 収まるので、その近道を通ってバッファを作らない）。
    /// 収まらない場合だけ `FlowKey` ごとのバッファへ積み、再度 判定する。
    pub fn feed(&mut self, key: FlowKey, seq: u32, payload: &[u8], now: Instant) -> FrameOutcome {
        if !self.flows.contains_key(&key) {
            match extract_sni(payload) {
                SniState::Fragmented => {} // 続けてバッファへ積む
                resolved => return FrameOutcome::Final(resolved),
            }
            self.evict_oldest_if_at_capacity();
        }

        let flow = self.flows.entry(key).or_insert_with(|| PendingFlow {
            base_seq: seq,
            data: Vec::new(),
            last_seen: now,
        });
        flow.last_seen = now;

        // 過去（再送）はデータを持っているので無視する。
        // 未来（順序違反・欠落）は誤ったデータをつなぐ危険があるので
        // 同様に無視し、次の segment を待つ（fail-open。安全側に倒す）。
        let expected = flow.base_seq.wrapping_add(flow.data.len() as u32);
        if seq_diff(seq, expected) == 0 {
            flow.data.extend_from_slice(payload);
        }

        if flow.data.len() > MAX_BUFFERED_BYTES {
            self.flows.remove(&key);
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::reassemble_buffer_overflow(crate::i18n::locale(), MAX_BUFFERED_BYTES)
            ));
            return FrameOutcome::Final(SniState::Fragmented);
        }

        match extract_sni(&flow.data) {
            SniState::Fragmented => FrameOutcome::Pending,
            resolved => {
                self.flows.remove(&key);
                FrameOutcome::Final(resolved)
            }
        }
    }

    /// `FLOW_TTL` を超えた接続を払い出し、内部から削除する。呼び出し側は
    /// 返った `FlowKey` を `SniState::Fragmented` として1行 log に書く
    /// （ClientHello は接続の最初に来るので、これ以上 待つ意味が無い）。
    pub fn expire_stale(&mut self, now: Instant) -> Vec<FlowKey> {
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| now.saturating_duration_since(flow.last_seen) > FLOW_TTL)
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.flows.remove(key);
        }
        expired
    }

    /// 溜めている接続数が上限に達していたら、最も古い接続を1つ捨てる。
    /// 捨てた接続は log に残さない（`[warn]` だけ出す。容量上限による
    /// 強制退去は稀で、実害は「また最初から組み立て直す」だけに留まる）。
    fn evict_oldest_if_at_capacity(&mut self) {
        if self.flows.len() < MAX_TRACKED_FLOWS {
            return;
        }
        if let Some(oldest) = self
            .flows
            .iter()
            .min_by_key(|(_, flow)| flow.last_seen)
            .map(|(key, _)| *key)
        {
            self.flows.remove(&oldest);
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::reassemble_flow_limit_reached(
                    crate::i18n::locale(),
                    MAX_TRACKED_FLOWS
                )
            ));
        }
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(src_port: u16) -> FlowKey {
        FlowKey {
            proto: crate::flow::Proto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            src_port,
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 66, 147, 243)),
            dst_port: 443,
        }
    }

    /// SNI を1つ持つ ClientHello の生 byte 列を組み立てる（`sni.rs` の
    /// test fixture と同じ形）。
    fn build_client_hello(host: &[u8]) -> Vec<u8> {
        let mut sni_ext_data = Vec::new();
        let entry_len = 1 + 2 + host.len();
        sni_ext_data.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext_data.push(0x00);
        sni_ext_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn single_packet_resolves_immediately_without_buffering() {
        // 大多数の ClientHello はこの近道を通る。
        let mut r = Reassembler::new();
        let packet = build_client_hello(b"example.com");
        let outcome = r.feed(key(1), 1000, &packet, Instant::now());
        assert_eq!(
            outcome,
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
    }

    #[test]
    fn non_tls_payload_resolves_to_none_immediately() {
        let mut r = Reassembler::new();
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let outcome = r.feed(key(2), 1000, http, Instant::now());
        assert_eq!(outcome, FrameOutcome::Final(SniState::None));
    }

    #[test]
    fn split_across_two_segments_resolves_once_joined() {
        // record header の宣言 length を実体の全長に合わせつつ、生の byte 列を
        // 2つの TCP segment（連続する seq）へ分割して投入する。
        let packet = build_client_hello(b"example.com");
        let mid = packet.len() / 2;
        let (first, second) = packet.split_at(mid);

        let mut r = Reassembler::new();
        let k = key(3);
        let now = Instant::now();
        let outcome1 = r.feed(k, 1000, first, now);
        assert_eq!(outcome1, FrameOutcome::Pending);

        let outcome2 = r.feed(k, 1000 + first.len() as u32, second, now);
        assert_eq!(
            outcome2,
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
    }

    #[test]
    fn out_of_order_segment_is_ignored_and_stays_pending() {
        // 最初の segment でバッファを作った後、本来の位置より先（ギャップが
        // 在る）の位置に2つ目の segment が届くと、そのまま無視して Pending を
        // 維持する（誤ったデータを連結しない）。
        let packet = build_client_hello(b"example.com");
        let mid = packet.len() / 2;
        let (first, second) = packet.split_at(mid);

        let mut r = Reassembler::new();
        let k = key(4);
        let now = Instant::now();
        let outcome1 = r.feed(k, 1000, first, now);
        assert_eq!(outcome1, FrameOutcome::Pending);

        // 本来の seq より1つ先（ギャップが在る）の位置に second を送る。
        let outcome_wrong = r.feed(k, 1000 + first.len() as u32 + 1, second, now);
        assert_eq!(outcome_wrong, FrameOutcome::Pending);

        // 正しい位置に送れば組み上がる。
        let outcome2 = r.feed(k, 1000 + first.len() as u32, second, now);
        assert_eq!(
            outcome2,
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
    }

    #[test]
    fn retransmitted_segment_is_ignored() {
        let packet = build_client_hello(b"example.com");
        let mid = packet.len() / 2;
        let (first, second) = packet.split_at(mid);

        let mut r = Reassembler::new();
        let k = key(5);
        let now = Instant::now();
        assert_eq!(r.feed(k, 1000, first, now), FrameOutcome::Pending);
        // 同じ segment（再送）をもう一度 送っても二重に連結されない。
        assert_eq!(r.feed(k, 1000, first, now), FrameOutcome::Pending);
        assert_eq!(
            r.feed(k, 1000 + first.len() as u32, second, now),
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
    }

    #[test]
    fn gives_up_when_buffer_exceeds_capacity() {
        let mut r = Reassembler::new();
        let k = key(6);
        let now = Instant::now();
        // record header だけを送り、続きが来ない体で巨大な宣言 length にする。
        let mut first = vec![0x16, 0x03, 0x01, 0xFF, 0xFF]; // length=0xFFFF
        first.extend_from_slice(&[0u8; 100]);
        assert_eq!(r.feed(k, 1000, &first, now), FrameOutcome::Pending);

        // 上限を超えるまで断片を送り続ける。
        let mut seq = 1000 + first.len() as u32;
        let mut outcome = FrameOutcome::Pending;
        for _ in 0..(MAX_BUFFERED_BYTES / 100 + 2) {
            let chunk = vec![0u8; 100];
            outcome = r.feed(k, seq, &chunk, now);
            seq += chunk.len() as u32;
            if outcome == FrameOutcome::Final(SniState::Fragmented) {
                break;
            }
        }
        assert_eq!(outcome, FrameOutcome::Final(SniState::Fragmented));
    }

    #[test]
    fn expire_stale_returns_flow_after_ttl_and_forgets_it() {
        let mut r = Reassembler::new();
        let k = key(7);
        let now = Instant::now();
        let packet = build_client_hello(b"example.com");
        let (first, _second) = packet.split_at(packet.len() / 2);
        assert_eq!(r.feed(k, 1000, first, now), FrameOutcome::Pending);

        let not_yet = now + Duration::from_secs(10);
        assert_eq!(r.expire_stale(not_yet), Vec::<FlowKey>::new());

        let after_ttl = now + Duration::from_secs(31);
        assert_eq!(r.expire_stale(after_ttl), vec![k]);
        // 二度目は何も返らない（既に忘れている）。
        assert_eq!(r.expire_stale(after_ttl), Vec::<FlowKey>::new());
    }

    #[test]
    fn evicts_oldest_flow_when_tracked_flow_capacity_is_reached() {
        let mut r = Reassembler::new();
        let now = Instant::now();
        let packet = build_client_hello(b"example.com");
        let (first, _second) = packet.split_at(packet.len() / 2);

        // 上限まで別々の flow を Pending 状態のまま積む。
        for i in 0..MAX_TRACKED_FLOWS {
            let port = (i % 60000) as u16 + 1024;
            let t = now + Duration::from_millis(i as u64);
            let outcome = r.feed(key(port), 1000, first, t);
            assert_eq!(outcome, FrameOutcome::Pending);
        }
        assert_eq!(r.flows.len(), MAX_TRACKED_FLOWS);

        // 1つ増やすと、最も古い（最初の）flow が捨てられ、総数は上限のまま。
        let extra_port = 60999;
        let t = now + Duration::from_secs(1);
        let outcome = r.feed(key(extra_port), 1000, first, t);
        assert_eq!(outcome, FrameOutcome::Pending);
        assert_eq!(r.flows.len(), MAX_TRACKED_FLOWS);
    }
}
