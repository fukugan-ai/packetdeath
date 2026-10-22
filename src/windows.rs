//! packetdeath 段階1w（Windows / pktmon）。OS に依存しない判定 code
//! （`sni.rs` / `blocklist.rs` / `judge.rs`）を Windows のガワへ繋ぐ。
//!
//! # 方式（WinDivert を採らない理由）
//!
//! WinDivert は採らない。driver（`WinDivert64.sys`）の署名者が外部の組織
//! （`C=CN`）で、driver 導入の制約に触れるためである（`docs/design.md`
//! 「採らない手段」が正本）。**pktmon（Windows 標準・追加 driver ゼロ）+
//! `SetTcpEntry`** で実装する。受入 ID は PW-0〜PW-5。
//!
//! # pktmon を packetdeath が起動するか（判断）
//!
//! **起動しない。** `linux.rs` が iptables の rule を一切 打たない設計
//! （`docs/design.md`「制約」：「rule と driver は利用者が入れる。packetdeath は
//! iptables を打たず、driver も自動で入れない。抜き忘れが出ない形にする」）と
//! 同じ理由で、pktmon の `filter add` / `start` / `stop` も packetdeath からは
//! 呼ばない。
//!
//! 理由：pktmon の capture session は `pktmon stop` で初めて確定する
//! （実測①「pktmon stop」の後に「イベントは失われていません」と出る）。
//! packetdeath が `pktmon start` を呼んだ後に panic や kill で落ちると、
//! `pktmon stop` が呼ばれないまま capture session が動き続け、ETL が際限なく
//! 肥大化する（実測①で無 filter の capture が 369 MB になった例が示す通り）。
//! これは iptables の rule が「落ちたとき rule だけが残る」のと同じ形の事故
//! であり、Linux 側で避けた性質を Windows 側だけ持ち込む理由が無い。
//!
//! よって、pktmon の運用（`filter add` → `start` → `stop` →
//! `etl2pcap`）は利用者が行い、packetdeath は **変換済みの pcapng を読むだけ**
//! にする。
//!
//! # ETL からパケットを取り出す経路（判断）
//!
//! **`pktmon etl2pcap` で変換した pcapng を読む経路を選ぶ。** ETL 自体
//! （Event Tracing for Windows のバイナリ形式）は Microsoft 非公開の内部形式で
//! 版依存が高く、自前パーサは壊れやすい。pcapng は IETF が定める公開仕様
//! （安定した block 形式）であり、`etl2pcap` は Microsoft 公式の変換ツールで
//! ある。したがって pcapng を対象にパーサを書く方が保守できる
//! （`検索` [pktmon etl2pcap / pcapng サポート](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-pcapng-support)）。
//!
//! pktmon にはリアルタイム表示モードがある（`検索` [Pktmon real-time monitoring](https://www.bleepingcomputer.com/news/microsoft/windows-10-s-pktmon-sniffer-gets-real-time-monitoring-pcap-support/)）が、
//! それをプログラムから消費する経路（ETW real-time session の購読）は
//! `未確認` である。`etl2pcap` はオフライン一括変換であり、リアルタイムに
//! 読めるかどうかも `未確認` のまま扱う。段階1wの受入（PW-0〜PW-5）は
//! ファイル1本を読み切るパーサの正しさだけを問うため、この判断で足りる。
//! リアルタイム運用（何秒ごとに `stop` → `etl2pcap` → 読む、を回すか）は
//! この module の範囲外（利用者が打つ）。
//!
//! pktmon が Ethernet フレームを含めて記録するか、生 IP だけを記録するかも
//! `未確認`。両対応にするため [`inspect_captured_frame`] は Ethernet として
//! 解釈できなければ生 IP として解釈し直す。
//!
//! # `SetTcpEntry` を呼ばない（停止条件）
//!
//! `SetTcpEntry` は `windows` crate で `pub unsafe fn` として公開されている
//! （`検索`。安全にラップした crate は見当たらなかった）。この crate は
//! `Cargo.toml` に `unsafe_code = "forbid"`（`lints.rust`）を持ち、`lib.rs` も
//! `#![forbid(unsafe_code)]` を宣言している。`forbid` は `deny` と異なり
//! `#[allow]` で局所的に緩められないため、`SetTcpEntry` を呼ぶ経路はこの
//! crate の中に存在しない。
//!
//! `unsafe_code = "forbid"` を外さないと `SetTcpEntry` を呼べないため、
//! **`SetTcpEntry` の呼び出しは実装しない**。その代わり、呼び出しに必要な
//! `MIB_TCPROW` 相当の値を安全に組み立てて検証できるところ（[`TcpRowSpec`] /
//! [`build_tcp_row_spec`]）までを実装する。`forbid` を外す／`deny` へ変える／
//! 局所的に許す、のどれを採るかは利用者の判断が要る。

use crate::av::AvList;
use crate::blocklist::Blocklist;
use crate::flow::{FlowKey, Proto};
use crate::iplist::IpList;
use crate::judge::{run_judges, AvJudge, IpJudge, Judge, JudgeInput, Reason, SniJudge};
use crate::reassemble::{FrameOutcome, Reassembler};
use crate::sni::SniState;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

const PCAPNG_BLOCK_TYPE_ENHANCED_PACKET: u32 = 0x0000_0006;
/// Block header（type 4 + total length 4）と block 末尾の total length 繰り返し（4）を
/// 合わせた、pcapng block の最小 byte 数。
const PCAPNG_MIN_BLOCK_LEN: usize = 12;
/// Enhanced Packet Block の固定長部分（interface id 4 + timestamp high 4 +
/// timestamp low 4 + captured length 4 + original length 4）。
const PCAPNG_EPB_FIXED_LEN: usize = 20;

/// `data[at..at+4]` を little-endian `u32` として読む。範囲外なら `None`。
/// pktmon は x86/x64 Windows でしか動かないため、pcapng の byte order は
/// 常に little-endian として扱う（Section Header Block の byte-order magic は
/// 判定しない）。
fn read_u32_le(data: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// pcapng の1 block を覗き、`(block_type, block_total_length, body)` を返す。
/// `body` は block header と末尾の length 繰り返しを除いた中身。
///
/// 壊れている（宣言 length が短すぎる／4の倍数でない／実 byte 列を超える）
/// block に遭遇したら `None` を返す。呼び出し側はそこで読み取りを打ち切る。
fn read_pcapng_block(data: &[u8], cursor: usize) -> Option<(u32, usize, &[u8])> {
    let block_type = read_u32_le(data, cursor)?;
    let total_len = read_u32_le(data, cursor + 4)? as usize;
    if total_len < PCAPNG_MIN_BLOCK_LEN || !total_len.is_multiple_of(4) {
        return None;
    }
    let end = cursor.checked_add(total_len)?;
    let body = data.get(cursor + 8..end - 4)?;
    Some((block_type, total_len, body))
}

/// Enhanced Packet Block の body から packet data を取り出す。
/// 宣言された captured length が body に収まらなければ `None`。
fn read_enhanced_packet_data(body: &[u8]) -> Option<&[u8]> {
    let captured_len = read_u32_le(body, 16)? as usize;
    body.get(PCAPNG_EPB_FIXED_LEN..PCAPNG_EPB_FIXED_LEN + captured_len)
}

/// pcapng の byte 列から、Enhanced Packet Block の packet data を順に取り出す。
/// 途中で壊れた block に遭遇したら、そこで読み取りを止めて **それまでに
/// 読めた分だけ** を返す（fail-open。攻撃者が作れる byte 列で panic しない）。
///
/// `block_total_length` は毎回 `PCAPNG_MIN_BLOCK_LEN`（12）以上進むことが
/// [`read_pcapng_block`] で保証されるため、無限 loop にならない。
pub fn extract_pcapng_packets(data: &[u8]) -> Vec<&[u8]> {
    let mut packets = Vec::new();
    let mut cursor = 0usize;
    while let Some((block_type, total_len, body)) = read_pcapng_block(data, cursor) {
        if block_type == PCAPNG_BLOCK_TYPE_ENHANCED_PACKET {
            if let Some(packet) = read_enhanced_packet_data(body) {
                packets.push(packet);
            }
        }
        cursor += total_len;
    }
    if cursor < data.len() {
        // 壊れた block（宣言 length が短すぎる／4の倍数でない／実 byte 列を
        // 超える）に遭遇し、そこで読み取りを打ち切った（fail-open）。
        crate::flow::service_log(&format!(
            "packetdeath: [warn] {}",
            crate::i18n::pcapng_truncated(crate::i18n::locale(), cursor, data.len())
        ));
    }
    packets
}

/// ClientHello はクライアント→サーバの向きにしか出ない。TCP の正確な向き
/// 判定には SYN フラグを追った状態管理が要るが、段階1w の対象（TLS/HTTP の
/// ような「クライアントの一時 port からサーバの well-known port へ繋ぐ」
/// 通信）では、宛先 port が送信元 port より小さいことで近似できる（実測
/// の `flows.jsonl` で、戻りパケットは宛先 port が `32348` の
/// ような一時 port、往きは `443` だった。443 宛て行の 49.5% が戻りだった）。
/// 両方が高い port の通信は対象外になるが、fail-open（判定できない flow は
/// 通す）の範囲内であり、誤って遮断する側には倒れない。
fn is_client_to_server(src_port: u16, dst_port: u16) -> bool {
    dst_port < src_port
}

/// pcapng から取り出した1パケット分の byte 列を覗き、TCP flow の `FlowKey` と
/// SNI 判定の結果（[`FrameOutcome`]）を返す。まず Ethernet ヘッダの無い生 IP
/// として解釈し、それで読めなければ Ethernet フレームとして解釈し直す
/// （pktmon が Ethernet を含めるかは `未確認` なので両対応にする）。
///
/// **`from_ip` を先に試す。**`from_ethernet` は先頭14 byte を無条件に
/// destination/source MAC + EtherType として受理してしまい、生 IP の byte 列
/// （先頭が IPv4 header の `version`/`IHL` byte）を渡しても「不明な EtherType
/// の frame」として `Ok` を返すことがある。その `Ok` を先に受け取ると
/// `from_ip` へのフォールバックが起きず、生 IP を誤読する
/// （実測：`pw1_extracts_sni_when_frame_has_no_ethernet_header` で先に確認）。
/// 一方 `from_ip` は先頭 byte の上位4bit が `4`（IPv4）でなければ確実に
/// 失敗するため、Ethernet フレームを生 IP として誤読する事故は起きない。
///
/// IP/TCP header が壊れている、TCP 以外（UDP/ARP 等）、payload が空、
/// サーバ→クライアント方向（戻り。[`is_client_to_server`]）のいずれかなら
/// `None`。段階1w は TCP の ClientHello だけを対象とし、QUIC（UDP 443）は
/// 対象外（`docs/design.md`「QUIC」節：件数を記録するだけ）。
///
/// SNI が1 TCP segment に収まらない場合は `reassembler` へ積む
/// （`docs/design.md`「ClientHello の組み立て直し」節）。`FrameOutcome::Pending`
/// が返ったときは、呼び出し側はこの flow をまだ log に書かない。
pub fn inspect_captured_frame(
    frame: &[u8],
    reassembler: &mut Reassembler,
    now: Instant,
) -> Option<(FlowKey, FrameOutcome)> {
    let sliced = SlicedPacket::from_ip(frame)
        .ok()
        .or_else(|| SlicedPacket::from_ethernet(frame).ok())?;

    let (src_ip, dst_ip): (IpAddr, IpAddr) = match sliced.net? {
        NetSlice::Ipv4(v4) => (
            v4.header().source_addr().into(),
            v4.header().destination_addr().into(),
        ),
        NetSlice::Ipv6(v6) => (
            v6.header().source_addr().into(),
            v6.header().destination_addr().into(),
        ),
        NetSlice::Arp(_) => return None,
    };

    let TransportSlice::Tcp(tcp) = sliced.transport? else {
        return None;
    };
    let payload = tcp.payload();
    if payload.is_empty() {
        return None;
    }
    let src_port = tcp.source_port();
    let dst_port = tcp.destination_port();
    if !is_client_to_server(src_port, dst_port) {
        return None;
    }

    let key = FlowKey {
        proto: Proto::Tcp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    };
    let outcome = reassembler.feed(key, tcp.sequence_number(), payload, now);
    Some((key, outcome))
}

/// SNI と宛先 IP（段階5）・`--av`（段階6）が `blocklist` / `iplist` / `av`
/// に当たるかを見る。段階1w は DNS 応答を読まない（CNAME チェーン解決は
/// 段階3であり、この module の範囲外）ので `CnameJudge` は使わず、`--eve` /
/// `--ips-sids`（段階4）の Windows CLI 公開も範囲外なので `IdsJudge` も
/// 使わない。`judge.rs` の `Judge` trait・`SniJudge`・`IpJudge`・`AvJudge`
/// をそのまま使い、SNI → IP → av の順で当てる
/// （`docs/design.md`「判定を差し込む口」の段階番号順）。
pub fn judge_sni(
    blocklist: &Blocklist,
    iplist: &IpList,
    av: &AvList,
    sni_state: &SniState,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<Reason> {
    let sni_judge = SniJudge { blocklist };
    let ip_judge = IpJudge { iplist };
    let av_judge = AvJudge { av };
    let judges: [&dyn Judge; 3] = [&sni_judge, &ip_judge, &av_judge];
    let cname_matched_qnames = HashSet::new();
    let input = JudgeInput {
        sni_state,
        cname_matched_qnames: &cname_matched_qnames,
        dst_ip,
        dst_port,
    };
    run_judges(&judges, &input)
}

/// `SetTcpEntry` に渡す `MIB_TCPROW` 相当の値。`windows` crate の union 型
/// （`MIB_TCPROW_LH_0`）を経由すると field の読み取りが `unsafe` になるため、
/// `unsafe` を使わずに構築・検証できる独自表現を持つ。
///
/// `local` は自ホスト側（接続の送信元）、`remote` は宛先側。値はどちらも
/// `SetTcpEntry` が期待する形（`dwLocalAddr` / `dwRemoteAddr` 相当）で持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRowSpec {
    /// IPv4 アドレスの byte 列（`Ipv4Addr::octets()` の並び）を、そのまま
    /// little-endian `u32` として読んだ値。
    pub local_addr: u32,
    /// port を network byte order（big-endian）へ変換し、下位16bit に置いた値。
    pub local_port: u32,
    pub remote_addr: u32,
    pub remote_port: u32,
}

/// `key` から `TcpRowSpec` を組み立てる。`key.src_*` が自ホスト側（local）、
/// `key.dst_*` が宛先側（remote）に対応する。
/// `MIB_TCPROW` は IPv4 専用の API なので、IPv6 の `key` には `None` を返す。
/// TCP 以外の `key`（UDP）にも `None` を返す（`SetTcpEntry` は TCP 専用）。
pub fn build_tcp_row_spec(key: &FlowKey) -> Option<TcpRowSpec> {
    if key.proto != Proto::Tcp {
        return None;
    }
    let (IpAddr::V4(local_ip), IpAddr::V4(remote_ip)) = (key.src_ip, key.dst_ip) else {
        return None;
    };
    Some(TcpRowSpec {
        local_addr: u32::from_le_bytes(local_ip.octets()),
        local_port: u32::from(key.src_port.to_be()),
        remote_addr: u32::from_le_bytes(remote_ip.octets()),
        remote_port: u32::from(key.dst_port.to_be()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::Ipv4Addr;

    const SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    /// SNI を1つ持つ最小の TLS ClientHello を組み立てる（`sni.rs` の test
    /// fixture と同じ形。`sni.rs` の private helper は再利用せず、この
    /// module 内で完結させる）。
    fn build_client_hello(host: &[u8]) -> Vec<u8> {
        let mut sni_ext_data = Vec::new();
        let entry_len = 1 + 2 + host.len();
        sni_ext_data.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext_data.push(0x00); // host_name
        sni_ext_data.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
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
        handshake.push(0x01); // client_hello
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// TCP payload を積んだ Ethernet フレームを組み立てる。
    fn build_ethernet_tcp_frame(payload: &[u8]) -> Result<Vec<u8>, String> {
        let builder = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv4([192, 168, 200, 20], [172, 66, 147, 243], 64)
            .tcp(59012, 443, 1, 64240);
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut frame, payload)
            .map_err(|e| e.to_string())?;
        Ok(frame)
    }

    /// Enhanced Packet Block を1つ組み立てる（`extract_pcapng_packets` の
    /// test fixture）。
    fn build_enhanced_packet_block(packet: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // interface id
        body.extend_from_slice(&0u32.to_le_bytes()); // timestamp high
        body.extend_from_slice(&0u32.to_le_bytes()); // timestamp low
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // captured len
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // original len
        body.extend_from_slice(packet);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let total_len = (4 + 4 + body.len() + 4) as u32;
        let mut block = Vec::new();
        block.extend_from_slice(&PCAPNG_BLOCK_TYPE_ENHANCED_PACKET.to_le_bytes());
        block.extend_from_slice(&total_len.to_le_bytes());
        block.extend_from_slice(&body);
        block.extend_from_slice(&total_len.to_le_bytes());
        block
    }

    fn sample_key() -> FlowKey {
        FlowKey {
            proto: Proto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 200, 20)),
            src_port: 59012,
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 66, 147, 243)),
            dst_port: 443,
        }
    }

    #[test]
    fn pw0_negative_control_no_client_hello_yields_sni_none() -> Result<(), String> {
        // PK-0 相当の陰性対照。ClientHello を含まない TCP payload からは
        // SniState::None が返る。
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame = build_ethernet_tcp_frame(http)?;
        let mut reassembler = Reassembler::new();
        let (_, outcome) = inspect_captured_frame(&frame, &mut reassembler, Instant::now())
            .ok_or("frame should parse")?;
        assert_eq!(outcome, FrameOutcome::Final(SniState::None));
        Ok(())
    }

    #[test]
    fn pw1_extracts_sni_from_pcapng_enhanced_packet_block() -> Result<(), String> {
        // 実測①の ETL 相当（pcapng へ変換した後の Enhanced Packet Block）から
        // SNI を取り出せる。
        let client_hello = build_client_hello(b"example.com");
        let frame = build_ethernet_tcp_frame(&client_hello)?;
        let epb = build_enhanced_packet_block(&frame);

        let packets = extract_pcapng_packets(&epb);
        assert_eq!(packets.len(), 1);

        let mut reassembler = Reassembler::new();
        let (key, outcome) = inspect_captured_frame(packets[0], &mut reassembler, Instant::now())
            .ok_or("captured frame should parse")?;
        assert_eq!(
            outcome,
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
        assert_eq!(key.dst_port, 443);
        Ok(())
    }

    #[test]
    fn pw1_extracts_sni_when_frame_has_no_ethernet_header() -> Result<(), String> {
        // pktmon が Ethernet ヘッダを含めない場合（未確認の側）でも取れること。
        let client_hello = build_client_hello(b"example.com");
        let frame = build_ethernet_tcp_frame(&client_hello)?;
        // Ethernet header（14 byte）を剥がし、生 IP から始める byte 列にする。
        let ip_only = frame
            .get(14..)
            .ok_or("frame must be longer than 14 bytes")?;
        let mut reassembler = Reassembler::new();
        let (_, outcome) = inspect_captured_frame(ip_only, &mut reassembler, Instant::now())
            .ok_or("ip-only frame should parse")?;
        assert_eq!(
            outcome,
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
        Ok(())
    }

    #[test]
    fn is_client_to_server_accepts_low_destination_port() {
        // 往き：クライアントの一時 port からサーバの well-known port へ。
        assert!(is_client_to_server(59012, 443));
        assert!(is_client_to_server(59012, 80));
    }

    #[test]
    fn is_client_to_server_rejects_reply_direction() {
        // 戻り：サーバの well-known port からクライアントの一時 port へ
        // （実測の flows.jsonl の戻り行の形）。
        assert!(!is_client_to_server(443, 32348));
    }

    #[test]
    fn inspect_captured_frame_ignores_reply_direction_packet() -> Result<(), String> {
        // 戻り方向（src_port=443, dst_port=一時 port）の TCP フレームは
        // flow として記録しない（戻りパケットをログに残さない）。
        let builder = etherparse::PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv4([172, 66, 147, 243], [192, 168, 200, 20], 64)
            .tcp(443, 59012, 1, 64240);
        let payload = b"reply-direction-payload";
        let mut frame = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut frame, payload)
            .map_err(|e| e.to_string())?;

        let mut reassembler = Reassembler::new();
        assert_eq!(
            inspect_captured_frame(&frame, &mut reassembler, Instant::now()),
            None
        );
        Ok(())
    }

    #[test]
    fn inspect_captured_frame_joins_client_hello_split_across_two_frames() -> Result<(), String> {
        // 実測の再現：ClientHello が1 TCP segment に収まらず
        // 複数 packet に割れても、Reassembler が組み立て直して SNI を返す。
        let client_hello = build_client_hello(b"example.com");
        let mid = client_hello.len() / 2;
        let (first_half, second_half) = client_hello.split_at(mid);

        let seq_base: u32 = 1000;
        let frame1 = {
            let builder = etherparse::PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
                .ipv4([192, 168, 200, 20], [172, 66, 147, 243], 64)
                .tcp(59012, 443, seq_base, 64240);
            let mut f = Vec::with_capacity(builder.size(first_half.len()));
            builder
                .write(&mut f, first_half)
                .map_err(|e| e.to_string())?;
            f
        };
        let frame2 = {
            let builder = etherparse::PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
                .ipv4([192, 168, 200, 20], [172, 66, 147, 243], 64)
                .tcp(59012, 443, seq_base + first_half.len() as u32, 64240);
            let mut f = Vec::with_capacity(builder.size(second_half.len()));
            builder
                .write(&mut f, second_half)
                .map_err(|e| e.to_string())?;
            f
        };

        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        let (_, outcome1) =
            inspect_captured_frame(&frame1, &mut reassembler, now).ok_or("frame1 should parse")?;
        assert_eq!(outcome1, FrameOutcome::Pending);

        let (_, outcome2) =
            inspect_captured_frame(&frame2, &mut reassembler, now).ok_or("frame2 should parse")?;
        assert_eq!(
            outcome2,
            FrameOutcome::Final(SniState::Ok("example.com".to_string()))
        );
        Ok(())
    }

    #[test]
    fn pw2_empty_pcapng_yields_no_packets() {
        assert_eq!(extract_pcapng_packets(&[]), Vec::<&[u8]>::new());
    }

    #[test]
    fn pw2_truncated_block_does_not_panic() {
        // block header だけで本体が無い（total_length が実 byte 列を超える）。
        let mut data = Vec::new();
        data.extend_from_slice(&PCAPNG_BLOCK_TYPE_ENHANCED_PACKET.to_le_bytes());
        data.extend_from_slice(&1000u32.to_le_bytes()); // 嘘の length
        data.extend_from_slice(&[0u8; 8]); // 実体は8 byteしかない
        assert_eq!(extract_pcapng_packets(&data), Vec::<&[u8]>::new());
    }

    #[test]
    fn pw2_lying_captured_length_does_not_panic() -> Result<(), String> {
        // captured length が実際の block body より大きいと申告された block。
        let real_packet = build_ethernet_tcp_frame(b"short")?;
        let mut block = build_enhanced_packet_block(&real_packet);
        // captured length field（body 先頭から16byte目、block header 8byte を
        // 足した位置）を実体よりずっと大きい値へ書き換える。
        let caplen_at = 8 + 16;
        block[caplen_at..caplen_at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(extract_pcapng_packets(&block), Vec::<&[u8]>::new());
        Ok(())
    }

    #[test]
    fn pw2_huge_input_does_not_panic() {
        let huge = vec![0x41u8; 1_000_000];
        // 中身は block として無意味なので、panic しなければ良い
        // （block_type が偶然 6 に一致することはない）。
        let _ = extract_pcapng_packets(&huge);
    }

    #[test]
    fn pw2_zero_length_block_does_not_infinite_loop() {
        // total_length が最小値未満（無限 loop の罠）。
        let mut data = Vec::new();
        data.extend_from_slice(&PCAPNG_BLOCK_TYPE_ENHANCED_PACKET.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(extract_pcapng_packets(&data), Vec::<&[u8]>::new());
    }

    /// `judge_sni` の test は宛先 IP を見ない SNI 判定を確かめるので、iplist
    /// に当たらないダミー値で埋める。
    fn dummy_dst_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    /// `judge_sni` は段階4の `IdsJudge` を含まないので port は判定に効かない。
    /// 呼び出し規約を揃えるためのダミー値。
    fn dummy_dst_port() -> u16 {
        443
    }

    #[test]
    fn judge_sni_matches_blocklisted_host() {
        let blocklist = Blocklist::parse("ads.example\n");
        let iplist = IpList::empty();
        let av = AvList::empty();
        let sni_state = SniState::Ok("ads.example".to_string());
        assert_eq!(
            judge_sni(
                &blocklist,
                &iplist,
                &av,
                &sni_state,
                dummy_dst_ip(),
                dummy_dst_port()
            ),
            Some(Reason::Sni)
        );
    }

    #[test]
    fn judge_sni_passes_when_not_in_blocklist() {
        let blocklist = Blocklist::parse("ads.example\n");
        let iplist = IpList::empty();
        let av = AvList::empty();
        let sni_state = SniState::Ok("example.com".to_string());
        assert_eq!(
            judge_sni(
                &blocklist,
                &iplist,
                &av,
                &sni_state,
                dummy_dst_ip(),
                dummy_dst_port()
            ),
            None
        );
    }

    #[test]
    fn judge_sni_matches_ip_even_without_sni() {
        // 段階5：SNI を持たない flow（QUIC の中身が読めない等）も IP で落ちる。
        let blocklist = Blocklist::empty();
        let iplist = IpList::parse("93.184.216.34\n");
        let av = AvList::empty();
        let sni_state = SniState::None;
        assert_eq!(
            judge_sni(
                &blocklist,
                &iplist,
                &av,
                &sni_state,
                dummy_dst_ip(),
                dummy_dst_port()
            ),
            Some(Reason::Iplist)
        );
    }

    #[test]
    fn judge_sni_prefers_sni_reason_over_ip_when_both_match() {
        let blocklist = Blocklist::parse("ads.example\n");
        let iplist = IpList::parse("93.184.216.34\n");
        let av = AvList::empty();
        let sni_state = SniState::Ok("ads.example".to_string());
        assert_eq!(
            judge_sni(
                &blocklist,
                &iplist,
                &av,
                &sni_state,
                dummy_dst_ip(),
                dummy_dst_port()
            ),
            Some(Reason::Sni)
        );
    }

    #[test]
    fn judge_sni_matches_av_when_sni_and_iplist_pass() {
        // 段階6：SNI にも --iplist にも当たらない宛先が --av で落ちる
        // （`docs/design.md`「判定を差し込む口」の段階番号順、末尾が av）。
        let blocklist = Blocklist::empty();
        let iplist = IpList::empty();
        let content = format!(
            r#"{{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"{}","dst_port":{},"sha256":null,"verdict":"malicious","engine":"manual"}}"#,
            dummy_dst_ip(),
            dummy_dst_port()
        );
        let av = AvList::parse(&content);
        let sni_state = SniState::None;
        assert_eq!(
            judge_sni(
                &blocklist,
                &iplist,
                &av,
                &sni_state,
                dummy_dst_ip(),
                dummy_dst_port()
            ),
            Some(Reason::Av)
        );
    }

    #[test]
    fn pw3_build_tcp_row_spec_swaps_port_byte_order() -> Result<(), String> {
        // 受入 PW-3：443 -> 0xBB01（上位下位が入れ替わっていること）。
        let row = build_tcp_row_spec(&sample_key()).ok_or("ipv4/tcp key should build")?;
        assert_eq!(row.remote_port, 0xBB01);
        Ok(())
    }

    #[test]
    fn pw3_build_tcp_row_spec_keeps_ip_octet_order() -> Result<(), String> {
        // IP は GetAddressBytes（= octets()）の並びのまま u32 にする。
        let row = build_tcp_row_spec(&sample_key()).ok_or("ipv4/tcp key should build")?;
        let expected = u32::from_le_bytes([172, 66, 147, 243]);
        assert_eq!(row.remote_addr, expected);
        Ok(())
    }

    #[test]
    fn build_tcp_row_spec_returns_none_for_ipv6() {
        use std::net::Ipv6Addr;
        let key = FlowKey {
            proto: Proto::Tcp,
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            src_port: 1,
            dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_port: 443,
        };
        assert_eq!(build_tcp_row_spec(&key), None);
    }

    #[test]
    fn build_tcp_row_spec_returns_none_for_udp() {
        let mut key = sample_key();
        key.proto = Proto::Udp;
        assert_eq!(build_tcp_row_spec(&key), None);
    }
}
