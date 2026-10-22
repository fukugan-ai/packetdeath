//! 段階3「CNAME チェーン解決」。DNS 応答から CNAME チェーンと宛先 IP を取り出す。
//!
//! 入力は UDP payload（生 byte）。**外から来た byte を信じない**。DNS 応答は
//! 攻撃者が作れる（`docs/design.md`「制約」）。添字アクセスの前に必ず長さを
//! 確かめ、`panic` しない。
//!
//! **DNS の圧縮ポインタは無限ループを作れる。**ここでは「ポインタは必ず
//! 現在位置より前を指す」という制約で辿る先を単調減少させ、循環を構造的に
//! 禁止する（辿る回数にも上限を置く二重の安全策）。上限に達したら `Err` を
//! 返し、`panic` しない（テスト項目7）。

use crate::sni::read_u16;
use serde::Serialize;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Mutex;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const DNS_HEADER_LEN: usize = 12;
/// RFC 1035 4.1.4：ラベルを展開した後の domain name は 255 octet 以下。
const MAX_NAME_LEN: usize = 255;
/// 圧縮ポインタを辿る回数の上限。offset の単調減少だけでも循環は防げるが、
/// 二重の安全策として置く。
const MAX_POINTER_HOPS: usize = 128;

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;

/// 1 DNS 応答から取り出した、判定に使う材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub qname: String,
    /// CNAME の並び（応答が出てきた順序どおり）。
    pub chain: Vec<String>,
    pub addrs: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsParseError {
    /// header にすら届かない。
    TooShort,
    /// QR bit が立っていない（応答ではなく query）。
    NotAResponse,
    /// question section が無い（`qname` が取れない）。
    NoQuestion,
    /// domain name の読み取りに失敗した（長さ欄が嘘、圧縮ポインタの循環、
    /// 辿る回数の上限超過を含む）。
    BadName,
    /// resource record の読み取りに失敗した（長さ欄が実 byte 列を超える等）。
    BadRecord,
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locale = crate::i18n::locale();
        let s = match self {
            Self::TooShort => crate::i18n::dns_too_short(locale),
            Self::NotAResponse => crate::i18n::dns_not_a_response(locale),
            Self::NoQuestion => crate::i18n::dns_no_question(locale),
            Self::BadName => crate::i18n::dns_bad_name(locale),
            Self::BadRecord => crate::i18n::dns_bad_record(locale),
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for DnsParseError {}

/// `data[start..]` にある DNS の domain name（ラベル列・圧縮ポインタ）を読む。
///
/// 戻り値の `usize` は、この name の直後（圧縮ポインタを最初に使った場合は
/// その 2 byte の直後）の offset である。
fn read_name(data: &[u8], start: usize) -> Result<(String, usize), DnsParseError> {
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = start;
    let mut after_first_pointer: Option<usize> = None;
    let mut hops = 0usize;
    let mut total_len = 0usize;

    loop {
        let len_byte = *data.get(cursor).ok_or(DnsParseError::BadName)?;

        if len_byte == 0 {
            cursor = cursor.checked_add(1).ok_or(DnsParseError::BadName)?;
            break;
        }

        match len_byte & 0xC0 {
            0xC0 => {
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(DnsParseError::BadName);
                }
                let lo = *data.get(cursor + 1).ok_or(DnsParseError::BadName)?;
                let offset = (((len_byte & 0x3F) as usize) << 8) | lo as usize;
                if after_first_pointer.is_none() {
                    after_first_pointer =
                        Some(cursor.checked_add(2).ok_or(DnsParseError::BadName)?);
                }
                // INVARIANT: ポインタは必ず現在位置より前を指す。ジャンプの
                // たびに offset が単調減少するので、圧縮ポインタの循環は
                // 構造的に起こり得ない（有限回で `break` するか `Err` になる）。
                if offset >= cursor {
                    return Err(DnsParseError::BadName);
                }
                cursor = offset;
            }
            0x00 => {
                let label_len = len_byte as usize;
                let label_start = cursor.checked_add(1).ok_or(DnsParseError::BadName)?;
                let label_end = label_start
                    .checked_add(label_len)
                    .ok_or(DnsParseError::BadName)?;
                let label = data
                    .get(label_start..label_end)
                    .ok_or(DnsParseError::BadName)?;
                total_len = total_len
                    .checked_add(label_len + 1)
                    .ok_or(DnsParseError::BadName)?;
                if total_len > MAX_NAME_LEN {
                    return Err(DnsParseError::BadName);
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                cursor = label_end;
            }
            // 0x40 / 0x80 は未定義（RFC 1035 4.1.4 は 00 と 11 だけを定める）。
            _ => return Err(DnsParseError::BadName),
        }
    }

    let next = after_first_pointer.unwrap_or(cursor);
    Ok((labels.join("."), next))
}

/// UDP payload（DNS 応答）を parse し、`qname`・CNAME チェーン・宛先 IP を返す。
/// `panic` しない。
pub fn parse_dns_response(data: &[u8]) -> Result<DnsAnswer, DnsParseError> {
    if data.len() < DNS_HEADER_LEN {
        return Err(DnsParseError::TooShort);
    }
    let flags = read_u16(data, 2).ok_or(DnsParseError::TooShort)?;
    if flags & 0x8000 == 0 {
        return Err(DnsParseError::NotAResponse);
    }
    let qdcount = read_u16(data, 4).ok_or(DnsParseError::TooShort)?;
    let ancount = read_u16(data, 6).ok_or(DnsParseError::TooShort)?;
    if qdcount == 0 {
        return Err(DnsParseError::NoQuestion);
    }

    let mut cursor = DNS_HEADER_LEN;
    let mut qname = String::new();
    for i in 0..qdcount {
        let (name, next) = read_name(data, cursor)?;
        if i == 0 {
            qname = name;
        }
        // qtype(2) + qclass(2) を読み飛ばす。
        cursor = next.checked_add(4).ok_or(DnsParseError::BadRecord)?;
        if cursor > data.len() {
            return Err(DnsParseError::TooShort);
        }
    }

    let mut chain = Vec::new();
    let mut addrs = Vec::new();

    for _ in 0..ancount {
        let (_owner, after_name) = read_name(data, cursor)?;
        let class_at = after_name.checked_add(2).ok_or(DnsParseError::BadRecord)?;
        let ttl_at = class_at.checked_add(2).ok_or(DnsParseError::BadRecord)?;
        let rdlength_at = ttl_at.checked_add(4).ok_or(DnsParseError::BadRecord)?;
        let rtype = read_u16(data, after_name).ok_or(DnsParseError::TooShort)?;
        let rdlength = read_u16(data, rdlength_at).ok_or(DnsParseError::TooShort)? as usize;
        let rdata_start = rdlength_at.checked_add(2).ok_or(DnsParseError::BadRecord)?;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or(DnsParseError::BadRecord)?;
        let rdata = data
            .get(rdata_start..rdata_end)
            .ok_or(DnsParseError::TooShort)?;

        match rtype {
            QTYPE_CNAME => {
                let (cname, _) = read_name(data, rdata_start)?;
                chain.push(cname);
            }
            QTYPE_A => {
                if let Ok(octets) = <[u8; 4]>::try_from(rdata) {
                    addrs.push(IpAddr::V4(Ipv4Addr::from(octets)));
                }
            }
            QTYPE_AAAA => {
                if let Ok(octets) = <[u8; 16]>::try_from(rdata) {
                    addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
            }
            _ => {}
        }

        cursor = rdata_end;
    }

    Ok(DnsAnswer {
        qname,
        chain,
        addrs,
    })
}

/// `<log dir>/dns.jsonl` の1行分。field は `docs/design.md`「名前と置き場」の
/// DNS log が正本。
#[derive(Debug, Clone, Serialize)]
pub struct DnsLogEntry {
    pub ts: String,
    pub qname: String,
    pub chain: Vec<String>,
    pub addrs: Vec<IpAddr>,
    pub matched: Option<String>,
}

impl DnsLogEntry {
    /// `answer` の所有権を受け取り、`matched`（blocklist に当たった chain 要素。
    /// 無ければ `None`）を添えて log entry を作る。
    pub fn new(answer: DnsAnswer, matched: Option<String>) -> Result<Self, time::error::Format> {
        Ok(Self {
            ts: OffsetDateTime::now_utc().format(&Rfc3339)?,
            qname: answer.qname,
            chain: answer.chain,
            addrs: answer.addrs,
            matched,
        })
    }
}

/// `<log dir>/dns.jsonl` への追記と、開発中の stdout 複製を担う。
/// 実装は `crate::flow::FlowLogSink` と同形（1行1 JSON を append し、
/// `crate::flow::LogError` を共有する）。
pub struct DnsLogSink {
    file: Mutex<File>,
}

impl DnsLogSink {
    pub fn open(path: &Path) -> Result<Self, crate::flow::LogError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn write(&self, entry: &DnsLogEntry) -> Result<(), crate::flow::LogError> {
        let line = serde_json::to_string(entry)?;
        println!("{line}");

        let mut file = self.file.lock().map_err(|_| crate::flow::LogError::Lock)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 圧縮ポインタを使わない、素直な DNS 応答（qname → CNAME 1件 → A 1件）を
    /// 組み立てる test 用 helper。
    fn build_dns_response(
        qname_labels: &[&str],
        cname_labels: &[&str],
        a_addr: [u8; 4],
    ) -> Vec<u8> {
        fn encode_name(labels: &[&str]) -> Vec<u8> {
            let mut out = Vec::new();
            for label in labels {
                out.push(label.len() as u8);
                out.extend_from_slice(label.as_bytes());
            }
            out.push(0);
            out
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x12, 0x34]); // id
        msg.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
        msg.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
        msg.extend_from_slice(&[0x00, 0x02]); // ancount = 2 (CNAME + A)
        msg.extend_from_slice(&[0x00, 0x00]); // nscount = 0
        msg.extend_from_slice(&[0x00, 0x00]); // arcount = 0

        // question
        msg.extend_from_slice(&encode_name(qname_labels));
        msg.extend_from_slice(&[0x00, 0x01]); // qtype = A
        msg.extend_from_slice(&[0x00, 0x01]); // qclass = IN

        // answer 1: qname の CNAME
        msg.extend_from_slice(&encode_name(qname_labels));
        msg.extend_from_slice(&QTYPE_CNAME.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]); // class IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // ttl = 60
        let cname_encoded = encode_name(cname_labels);
        msg.extend_from_slice(&(cname_encoded.len() as u16).to_be_bytes());
        msg.extend_from_slice(&cname_encoded);

        // answer 2: cname の A レコード
        msg.extend_from_slice(&encode_name(cname_labels));
        msg.extend_from_slice(&QTYPE_A.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        msg.extend_from_slice(&[0x00, 0x04]); // rdlength = 4
        msg.extend_from_slice(&a_addr);

        msg
    }

    #[test]
    fn parses_qname_chain_and_addr_from_valid_response() -> Result<(), String> {
        // テスト項目8。
        let msg = build_dns_response(
            &["first-party", "example"],
            &["tracker", "ads-example"],
            [93, 184, 216, 34],
        );
        let answer = parse_dns_response(&msg).map_err(|e| e.to_string())?;
        assert_eq!(answer.qname, "first-party.example");
        assert_eq!(answer.chain, vec!["tracker.ads-example".to_string()]);
        assert_eq!(
            answer.addrs,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        Ok(())
    }

    #[test]
    fn rejects_empty_input() {
        // テスト項目7。
        assert_eq!(parse_dns_response(&[]), Err(DnsParseError::TooShort));
    }

    #[test]
    fn rejects_query_not_response() {
        let mut msg = build_dns_response(&["example", "com"], &["cdn", "example"], [1, 2, 3, 4]);
        msg[2] = 0x01; // QR bit を降ろす
        msg[3] = 0x00;
        assert_eq!(parse_dns_response(&msg), Err(DnsParseError::NotAResponse));
    }

    #[test]
    fn rejects_truncated_at_every_prefix_length_without_panicking() {
        // テスト項目7「切り詰め」。正常な応答を先頭から少しずつ切り、
        // 途中でも panic せず必ず `Result` が返ることを確かめる。
        let full = build_dns_response(&["example", "com"], &["cdn", "example"], [1, 2, 3, 4]);
        for len in 0..full.len() {
            let _ = parse_dns_response(&full[..len]);
        }
    }

    #[test]
    fn rejects_lying_rdlength_without_panicking() {
        // テスト項目7「長さ欄が嘘」。CNAME の rdlength を実体よりずっと大きくする。
        let mut msg = build_dns_response(&["example", "com"], &["cdn", "example"], [1, 2, 3, 4]);
        // 1つ目の answer の rdlength は、qname(2 labels) の直後の
        // name(2) + type(2) + class(2) + ttl(4) の 10 byte 分だけ質問より後ろ。
        // 具体的な offset を数えず、rdlength の 2 byte を総当りで巨大値へ
        // 書き換えても Err になり panic しないことだけを見る。
        for i in 0..msg.len().saturating_sub(1) {
            let mut corrupted = msg.clone();
            corrupted[i] = 0xFF;
            corrupted[i + 1] = 0xFF;
            let _ = parse_dns_response(&corrupted);
        }
        // 代表的に1件、明確に嘘の rdlength を仕込んだケースも見る。
        let last = msg.len();
        msg[last - 6] = 0xFF;
        msg[last - 5] = 0xFF;
        assert!(parse_dns_response(&msg).is_err());
    }

    #[test]
    fn rejects_self_referencing_compression_pointer_without_looping() {
        // テスト項目7「圧縮ポインタの循環」。question の name を、
        // 自分自身（header 直後の offset 12）を指すポインタ1個だけにする。
        let mut msg = vec![0u8; DNS_HEADER_LEN + 2];
        msg[2] = 0x81;
        msg[3] = 0x80; // QR=1
        msg[4] = 0x00;
        msg[5] = 0x01; // qdcount = 1
        msg[12] = 0xC0;
        msg[13] = 0x0C; // offset 12 = 自分自身
        let result = parse_dns_response(&msg);
        assert_eq!(result, Err(DnsParseError::BadName));
    }

    #[test]
    fn rejects_forward_referencing_pointer_chain_without_looping() {
        // 2つのポインタが互いに後方（自分より大きい offset）を指し合う形。
        // 単調減少制約で1回目のジャンプの時点で拒否される。
        let mut msg = vec![0u8; DNS_HEADER_LEN + 4];
        msg[2] = 0x81;
        msg[3] = 0x80;
        msg[4] = 0x00;
        msg[5] = 0x01;
        msg[12] = 0xC0;
        msg[13] = 0x0E; // offset 14 を指す（自分より後ろ）
        msg[14] = 0xC0;
        msg[15] = 0x0C; // offset 12 を指す（さらに前へ戻る）
        assert_eq!(parse_dns_response(&msg), Err(DnsParseError::BadName));
    }

    #[test]
    fn rejects_huge_but_meaningless_input_without_panicking() {
        // テスト項目7「巨大」。
        let huge = vec![0x41u8; 1_000_000];
        let _ = parse_dns_response(&huge);
    }

    #[test]
    fn ten_thousand_random_dns_like_messages_never_panic() {
        // テスト項目7の総仕上げ。QR bit だけ応答らしく立てたヘッダ + 完全に
        // ランダムな残り byte 列を1万本 食わせ、panic しないことだけを見る
        // （xorshift64。外部 crate に依存しない決定的な乱数）。
        let mut state = 0x2026_0911_u64;
        let mut next_u64 = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..10_000 {
            let len = DNS_HEADER_LEN + (next_u64() % 512) as usize;
            let mut msg = vec![0u8; len];
            msg[2] = 0x80; // QR=1（応答扱いにして先の parse 経路まで進ませる）
            for byte in msg.iter_mut().skip(DNS_HEADER_LEN) {
                *byte = (next_u64() & 0xFF) as u8;
            }
            let _ = parse_dns_response(&msg);
        }
    }

    #[test]
    fn rejects_missing_question_without_panicking() {
        let mut msg = vec![0u8; DNS_HEADER_LEN];
        msg[2] = 0x81;
        msg[3] = 0x80;
        assert_eq!(parse_dns_response(&msg), Err(DnsParseError::NoQuestion));
    }
}
