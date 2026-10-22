//! TLS ClientHello から SNI（Server Name Indication）を取り出す、OS に依存しないパーサ。
//!
//! 入力は 1 TCP セグメントの payload（生 byte）。**外から来た byte を信じない**。
//! 添字アクセスの前に必ず長さを確かめ、`panic` しない。
//!
//! `docs/design.md`「名前と置き場」の `sni_state` 契約に従い、判定結果を3つに
//! 区別する（`SniState`）。ClientHello が複数の TLS record や複数の TCP segment に
//! 分割されている場合は `Fragmented` を返す。段階1〜4 は TCP reassembly を持たない
//! ので、それ以上は追わない（`docs/design.md:96` 「段階1〜4 は segment を組み立て
//! 直さない」）。

/// TLS record header の固定長（type 1 + version 2 + length 2）。
const RECORD_HEADER_LEN: usize = 5;
/// Handshake message header の固定長（msg_type 1 + length（u24）3）。
const HANDSHAKE_HEADER_LEN: usize = 4;
/// ClientHello 本体で SNI 判定の前に無条件で読み飛ばす長さ（client_version 2 + random 32）。
const CLIENT_HELLO_FIXED_LEN: usize = 34;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_TYPE_SERVER_NAME: u16 = 0x0000;
const SERVER_NAME_TYPE_HOST_NAME: u8 = 0x00;

/// `docs/design.md`「名前と置き場」の `sni_state` フィールドと1対1に対応する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniState {
    /// SNI を取り出せた。
    Ok(String),
    /// 判定はできたが SNI が無い。内部では6つの原因を区別する（`NoSniReason`）が、
    /// `flows.jsonl` の `sni_state` はこの1値のまま畳む。`extract_sni` が
    /// `[debug]` log でどの原因かを出す。
    None,
    /// ClientHello が複数 TLS record／複数 TCP segment に分割されていて、
    /// この byte 列だけでは判定できない。
    Fragmented,
}

/// `SniState::None` に畳まれる前の、内部限定の詳細原因。6つある。
/// `flows.jsonl` へは出さない（`SniState` の3値契約を変えないため）。
/// `[debug]` log の文言と1対1に対応させ、判定を差し替えるときに追える形にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoSniReason {
    /// TLS record header（5 byte）にも満たない。
    TooShortForRecordHeader,
    /// 先頭 byte が Handshake（`0x16`）でない＝非 TLS。
    NotHandshakeRecord,
    /// Handshake ではあるが ClientHello（type 1）でない。
    NotClientHello,
    /// ClientHello 本体に extensions block が無い（TLS 1.2 以前など）。
    NoExtensionsBlock,
    /// extensions block を walk したが `server_name` 型の拡張が無い。
    NoServerNameExtension,
    /// `server_name` 拡張は在るが `host_name` 型の entry が無い。
    NoHostNameEntry,
}

impl NoSniReason {
    fn as_log_str(self) -> &'static str {
        match self {
            Self::TooShortForRecordHeader => "too_short_for_record_header",
            Self::NotHandshakeRecord => "not_handshake_record",
            Self::NotClientHello => "not_client_hello",
            Self::NoExtensionsBlock => "no_extensions_block",
            Self::NoServerNameExtension => "no_server_name_extension",
            Self::NoHostNameEntry => "no_host_name_entry",
        }
    }
}

impl SniState {
    /// log の `sni` field に書く値。
    pub fn sni(&self) -> Option<&str> {
        match self {
            Self::Ok(name) => Some(name.as_str()),
            Self::None | Self::Fragmented => None,
        }
    }

    /// log の `sni_state` field に書く文字列。
    pub fn as_log_str(&self) -> &'static str {
        match self {
            Self::Ok(_) => "ok",
            Self::None => "none",
            Self::Fragmented => "fragmented",
        }
    }
}

/// record／handshake の境界がこの byte 列の中で完結しない（＝続きが別 segment に
/// あるはず）ことを表す内部 marker。呼び出し元の `extract_sni` だけがこれを
/// `SniState::Fragmented` へ変換する。
#[derive(Debug, PartialEq, Eq)]
struct Incomplete;

/// `data[at..at+2]` を big-endian `u16` として読む。範囲外なら `None`。
/// `crate::dns` も DNS メッセージの同じ big-endian 整形を読むため共有する。
pub(crate) fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    let a = *data.get(at)?;
    let b = *data.get(at + 1)?;
    Some(u16::from_be_bytes([a, b]))
}

/// `data[at..at+3]` を big-endian `u24`（`u32` に格納）として読む。範囲外なら `None`。
fn read_u24(data: &[u8], at: usize) -> Option<u32> {
    let a = *data.get(at)?;
    let b = *data.get(at + 1)?;
    let c = *data.get(at + 2)?;
    Some(u32::from_be_bytes([0, a, b, c]))
}

/// TCP payload から SNI を1つ取り出す。`docs/design.md` の `sni_state` 契約に沿った
/// `SniState` を返す。`panic` しない。
///
/// SNI が無いと判定したときは、6つの内部原因のどれに当たったかを `[debug]` で
/// 出す。1接続あたり最大1回で、`flows.jsonl` の `sni_state` field は増やさない
/// （`NoSniReason` は log にだけ出す）。
pub fn extract_sni(tcp_payload: &[u8]) -> SniState {
    match parse(tcp_payload) {
        Ok(Ok(name)) => SniState::Ok(name),
        Ok(Err(reason)) => {
            crate::flow::service_log(&format!(
                "packetdeath: [debug] {}",
                crate::i18n::sni_absent(crate::i18n::locale(), reason.as_log_str())
            ));
            SniState::None
        }
        Err(Incomplete) => SniState::Fragmented,
    }
}

fn parse(tcp_payload: &[u8]) -> Result<Result<String, NoSniReason>, Incomplete> {
    let record_payload = match parse_tls_record(tcp_payload)? {
        Ok(fragment) => fragment,
        Err(reason) => return Ok(Err(reason)),
    };
    let handshake_body = match parse_handshake_message(record_payload)? {
        Ok(body) => body,
        Err(reason) => return Ok(Err(reason)),
    };
    let extensions = match parse_client_hello_extensions(handshake_body)? {
        Ok(ext) => ext,
        Err(reason) => return Ok(Err(reason)),
    };
    find_server_name(extensions)
}

/// TLS record header を読む。
///
/// - record header（5 byte）にも満たない → `Ok(Err(TooShortForRecordHeader))`
/// - 非 Handshake record（＝非 TLS）→ `Ok(Err(NotHandshakeRecord))`
/// - record 全体が header だけで判定できるほど短くない場合に、宣言 length が
///   `data` へ収まらない → `Err(Incomplete)`（この record は次の TCP segment へ続く）
/// - 収まる → `Ok(Ok(fragment))`
fn parse_tls_record(data: &[u8]) -> Result<Result<&[u8], NoSniReason>, Incomplete> {
    if data.len() < RECORD_HEADER_LEN {
        return Ok(Err(NoSniReason::TooShortForRecordHeader));
    }
    if data[0] != CONTENT_TYPE_HANDSHAKE {
        return Ok(Err(NoSniReason::NotHandshakeRecord));
    }
    // INVARIANT: 直前の長さ確認で `data.len() >= RECORD_HEADER_LEN` が成り立つので、
    // index 3..5 は必ず存在する。
    let length = read_u16(data, 3).ok_or(Incomplete)? as usize;
    let fragment = data
        .get(RECORD_HEADER_LEN..RECORD_HEADER_LEN + length)
        .ok_or(Incomplete)?;
    Ok(Ok(fragment))
}

/// Handshake header を読む。
///
/// - handshake message 以外（ClientHello 以外）→ `Ok(Err(NotClientHello))`
/// - record fragment 自体は完結しているのに、その中に handshake header すら
///   収まらない、または宣言 length が fragment を超える → `Err(Incomplete)`
///   （ClientHello が複数 record に分割されている状態）
fn parse_handshake_message(
    record_payload: &[u8],
) -> Result<Result<&[u8], NoSniReason>, Incomplete> {
    if record_payload.len() < HANDSHAKE_HEADER_LEN {
        return Err(Incomplete);
    }
    if record_payload[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Ok(Err(NoSniReason::NotClientHello));
    }
    let length = read_u24(record_payload, 1).ok_or(Incomplete)? as usize;
    let body = record_payload
        .get(HANDSHAKE_HEADER_LEN..HANDSHAKE_HEADER_LEN + length)
        .ok_or(Incomplete)?;
    Ok(Ok(body))
}

/// ClientHello 本体（`client_version` から）を読み飛ばして extensions block を返す。
///
/// - extensions block 自体が存在しない ClientHello（TLS 1.2 以前で拡張を1つも
///   持たない場合）→ `Ok(Err(NoExtensionsBlock))`（「壊れている」ではなく「SNI が無い」）
/// - 途中の length prefix が実 byte 列に届かない → `Err(Incomplete)`
///   （長さ欄が嘘、または後続 segment を必要とする）
fn parse_client_hello_extensions(body: &[u8]) -> Result<Result<&[u8], NoSniReason>, Incomplete> {
    if body.len() < CLIENT_HELLO_FIXED_LEN {
        return Err(Incomplete);
    }
    let mut cursor = CLIENT_HELLO_FIXED_LEN;

    // session_id: 1 byte length prefix
    let session_id_len = *body.get(cursor).ok_or(Incomplete)? as usize;
    cursor += 1 + session_id_len;

    // cipher_suites: 2 byte length prefix
    let cipher_suites_len = read_u16(body, cursor).ok_or(Incomplete)? as usize;
    cursor += 2 + cipher_suites_len;

    // compression_methods: 1 byte length prefix
    let compression_len = *body.get(cursor).ok_or(Incomplete)? as usize;
    cursor += 1 + compression_len;

    // extensions は ClientHello の末尾なので、無ければ「拡張なし」で正常終了する。
    if cursor == body.len() {
        return Ok(Err(NoSniReason::NoExtensionsBlock));
    }

    let extensions_len = read_u16(body, cursor).ok_or(Incomplete)? as usize;
    cursor += 2;
    let extensions = body
        .get(cursor..cursor + extensions_len)
        .ok_or(Incomplete)?;
    Ok(Ok(extensions))
}

/// extensions block を walk して `server_name`（SNI）拡張を探し、host_name を返す。
/// walk し終えても `server_name` 型の拡張が無ければ `NoServerNameExtension`。
fn find_server_name(extensions: &[u8]) -> Result<Result<String, NoSniReason>, Incomplete> {
    const EXTENSION_HEADER_LEN: usize = 4; // type 2 + length 2

    let mut cursor = 0usize;
    while cursor + EXTENSION_HEADER_LEN <= extensions.len() {
        let ext_type = read_u16(extensions, cursor).ok_or(Incomplete)?;
        let ext_len = read_u16(extensions, cursor + 2).ok_or(Incomplete)? as usize;
        let data_start = cursor + EXTENSION_HEADER_LEN;
        let ext_data = extensions
            .get(data_start..data_start + ext_len)
            .ok_or(Incomplete)?;

        if ext_type == EXTENSION_TYPE_SERVER_NAME {
            return parse_server_name_extension(ext_data);
        }
        cursor = data_start + ext_len;
    }
    Ok(Err(NoSniReason::NoServerNameExtension))
}

/// `server_name` 拡張の中身（`ServerNameList`）から最初の `host_name` を取り出す。
/// walk し終えても `host_name` 型の entry が無ければ `NoHostNameEntry`。
///
/// SNI の byte 列は仕様上 ASCII だが、外から来た値を前提にしない。非 ASCII や
/// NUL が混ざっていても `panic` せず、`String::from_utf8_lossy` で置換して返す
/// （JSON へ出すときは serde_json が制御文字を安全にエスケープする）。
fn parse_server_name_extension(data: &[u8]) -> Result<Result<String, NoSniReason>, Incomplete> {
    let list_len = read_u16(data, 0).ok_or(Incomplete)? as usize;
    let list = data.get(2..2 + list_len).ok_or(Incomplete)?;

    let mut cursor = 0usize;
    while cursor + 3 <= list.len() {
        let name_type = list[cursor];
        let name_len = read_u16(list, cursor + 1).ok_or(Incomplete)? as usize;
        let name_start = cursor + 3;
        let name_bytes = list
            .get(name_start..name_start + name_len)
            .ok_or(Incomplete)?;

        if name_type == SERVER_NAME_TYPE_HOST_NAME {
            return Ok(Ok(String::from_utf8_lossy(name_bytes).into_owned()));
        }
        cursor = name_start + name_len;
    }
    Ok(Err(NoSniReason::NoHostNameEntry))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SNI を1つ持つ最小の ClientHello を組み立てる test 用 helper。
    /// `host_name_bytes` は非 ASCII / NUL の耐性を試すため生 byte で受け取る。
    fn build_client_hello(host_name_bytes: &[u8]) -> Vec<u8> {
        let mut sni_ext_data = Vec::new();
        let server_name_entry_len = 1 + 2 + host_name_bytes.len();
        sni_ext_data.extend_from_slice(&(server_name_entry_len as u16).to_be_bytes());
        sni_ext_data.push(SERVER_NAME_TYPE_HOST_NAME);
        sni_ext_data.extend_from_slice(&(host_name_bytes.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(host_name_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXTENSION_TYPE_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        body.extend_from_slice(&[0x00, 0x2f]); // cipher_suites
        body.push(1); // compression_methods_len = 1
        body.push(0); // compression_methods
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]); // u24
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn rejects_non_tls_payload_as_no_sni() {
        // T-1 / PK-3 の陰性対照。HTTP の平文 request は非 TLS record なので None。
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_sni(http), SniState::None);
    }

    #[test]
    fn rejects_random_bytes_as_no_sni() {
        let random = [0xAAu8; 64];
        assert_eq!(extract_sni(&random), SniState::None);
    }

    #[test]
    fn extracts_sni_from_valid_client_hello() {
        // PK-1 / T-2 相当。既知の byte 列から SNI を取れることを確かめる。
        let packet = build_client_hello(b"example.com");
        assert_eq!(
            extract_sni(&packet),
            SniState::Ok("example.com".to_string())
        );
    }

    #[test]
    fn returns_fragmented_when_client_hello_spans_multiple_records() {
        // テスト項目3。record の宣言 length を本体より小さく切り詰め、
        // record fragment 自体がこの byte 列に収まらない状態を作る。
        let mut packet = build_client_hello(b"example.com");
        packet[3] = 0x00;
        packet[4] = 0x01;
        assert_eq!(extract_sni(&packet), SniState::Fragmented);
    }

    #[test]
    fn returns_fragmented_when_handshake_length_exceeds_record() {
        // handshake header の length（u24）を実際の record fragment より
        // 大きく書き換える。ClientHello が record を跨いでいる状態に相当する。
        let mut packet = build_client_hello(b"example.com");
        // record header 5 byte + msg_type 1 byte の直後が handshake length（u24）の
        // 最上位 byte（index 6）。index 9 は既に ClientHello body の先頭になる。
        packet[6] = 0xFF;
        assert_eq!(extract_sni(&packet), SniState::Fragmented);
    }

    #[test]
    fn returns_fragmented_when_length_field_is_larger_than_actual_bytes() {
        // テスト項目4。extensions の宣言 length を実際より大きくする。
        let mut packet = build_client_hello(b"example.com");
        let last = packet.len();
        packet.truncate(last - 4); // 末尾を削り、宣言 length と実体を食い違わせる
        assert_eq!(extract_sni(&packet), SniState::Fragmented);
    }

    #[test]
    fn returns_fragmented_when_length_field_is_smaller_than_actual_bytes() -> Result<(), String> {
        // 長さ欄が実際より小さい場合。record length を実体より小さくする
        // （返り値は record 直後の余り byte を無視するだけで、panic はしない）。
        let mut packet = build_client_hello(b"example.com");
        let declared =
            read_u16(&packet, 3).ok_or_else(|| "test packet has record header".to_string())?;
        let shorter = declared - 1;
        packet[3..5].copy_from_slice(&shorter.to_be_bytes());
        // 1 byte 短く申告すると、extensions 全体は record fragment の中に
        // 収まらなくなるため Fragmented になる（panic しないことが本題）。
        assert_eq!(extract_sni(&packet), SniState::Fragmented);
        Ok(())
    }

    #[test]
    fn returns_none_for_empty_input() {
        // テスト項目5。record header にすら届かない＝非 TLS と同じ扱い。
        assert_eq!(extract_sni(&[]), SniState::None);
    }

    #[test]
    fn returns_none_for_single_byte_input() {
        // テスト項目5。
        assert_eq!(extract_sni(&[0x16]), SniState::None);
    }

    #[test]
    fn returns_none_for_huge_but_meaningless_input() {
        // テスト項目5。巨大な byte 列でも panic しない。先頭が Handshake 以外なので None。
        let huge = vec![0x41u8; 1_000_000];
        assert_eq!(extract_sni(&huge), SniState::None);
    }

    #[test]
    fn does_not_panic_on_non_ascii_and_nul_in_sni() {
        // テスト項目6。非 ASCII（不正な UTF-8 の先頭 byte）と NUL を host_name に混ぜる。
        let dirty = [0xFFu8, 0x00, b'a', b'.', b'c', b'o', b'm'];
        let packet = build_client_hello(&dirty);
        // panic しなければ良く、結果は置換文字を含む文字列で構わない。
        assert!(matches!(extract_sni(&packet), SniState::Ok(_)));
    }

    #[test]
    fn returns_none_when_client_hello_has_no_extensions() {
        // 拡張ブロックそのものを持たない ClientHello（SNI 拡張なし）。
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        // extensions block を付けない。

        let mut handshake = Vec::new();
        handshake.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(extract_sni(&record), SniState::None);
    }

    #[test]
    fn sni_state_as_log_str_matches_design_contract() {
        // `docs/design.md`「名前と置き場」の `sni_state` 値（`ok` / `none` / `fragmented`）と一致すること。
        assert_eq!(SniState::Ok("x".to_string()).as_log_str(), "ok");
        assert_eq!(SniState::None.as_log_str(), "none");
        assert_eq!(SniState::Fragmented.as_log_str(), "fragmented");
    }

    // `SniState::None` に畳まれる6つの内部原因（`NoSniReason`）が、
    // それぞれ自分の return site から返ることを1つずつ確かめる。
    // `parse` は非公開だが `use super::*` でこの test module から呼べる。

    #[test]
    fn no_sni_reason_too_short_for_record_header() {
        // sni.rs の1つ目の return site：record header（5 byte）にも満たない。
        assert_eq!(
            parse(&[0x16, 0x03]),
            Ok(Err(NoSniReason::TooShortForRecordHeader))
        );
    }

    #[test]
    fn no_sni_reason_not_handshake_record() {
        // 2つ目の return site：先頭 byte が Handshake（0x16）でない。
        assert_eq!(
            parse(&[0x17, 0x03, 0x01, 0x00, 0x00]),
            Ok(Err(NoSniReason::NotHandshakeRecord))
        );
    }

    #[test]
    fn no_sni_reason_not_client_hello() {
        // 3つ目の return site：Handshake だが msg_type が ClientHello（1）でない
        // （ここでは 2 = ServerHello 相当）。
        let handshake_body: &[u8] = &[0x02, 0x00, 0x00, 0x00]; // msg_type=2, length=0
        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake_body.len() as u16).to_be_bytes());
        record.extend_from_slice(handshake_body);
        assert_eq!(parse(&record), Ok(Err(NoSniReason::NotClientHello)));
    }

    #[test]
    fn no_sni_reason_no_extensions_block() {
        // 4つ目の return site：ClientHello 本体に extensions block が無い。
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1); // compression_methods_len = 1
        body.push(0);
        // extensions block を付けない。

        let mut handshake = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(parse(&record), Ok(Err(NoSniReason::NoExtensionsBlock)));
    }

    /// `build_client_hello` と同じ骨格で、extensions block の中身だけ差し替える
    /// test 専用 helper。5つ目・6つ目の return site を作るのに使う。
    fn build_client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        let body_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&body_len[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn no_sni_reason_no_server_name_extension() {
        // 5つ目の return site：extensions block を walk し終えても server_name
        // 型（0x0000）の拡張が無い（ここでは適当な別 type 0x000a を1つ置く）。
        let other_ext_data: &[u8] = &[0x00, 0x1d]; // 中身は判定に使わないので何でもよい
        let mut other_ext = vec![0x00, 0x0a]; // type = 0x000a（server_name ではない）
        other_ext.extend_from_slice(&(other_ext_data.len() as u16).to_be_bytes());
        other_ext.extend_from_slice(other_ext_data);

        let record = build_client_hello_with_extensions(&other_ext);
        assert_eq!(parse(&record), Ok(Err(NoSniReason::NoServerNameExtension)));
    }

    #[test]
    fn no_sni_reason_no_host_name_entry() {
        // 6つ目の return site：server_name 拡張は在るが、ServerNameList の
        // entry が host_name 型（0x00）でない（ここでは 0x01 にする）。
        let name_bytes = b"example.com";
        let mut sni_ext_data = Vec::new();
        let entry_len = 1 + 2 + name_bytes.len();
        sni_ext_data.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext_data.push(0x01); // host_name（0x00）ではない
        sni_ext_data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext_data.extend_from_slice(name_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&EXTENSION_TYPE_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_data);

        let record = build_client_hello_with_extensions(&extensions);
        assert_eq!(parse(&record), Ok(Err(NoSniReason::NoHostNameEntry)));
    }
}
