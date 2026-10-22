//! 段階5「宛先 IP list」の `--iplist`。`docs/design.md`「段階5 以降と
//! 受入 ID の予約」節が正本。
//!
//! 形式は1行1 IP か CIDR。`#` で始まる行は無視。IPv4 と IPv6 の両方を持つ。
//! CIDR の判定は `std::net::Ipv4Addr::to_bits` / `Ipv6Addr::to_bits`
//! （Rust 1.80 で安定化）で足り、外部 crate は使わない。
//!
//! **外部が更新する iplist を、動作の gate にしない。**file が読めなくても
//! `IpList::empty()` へ倒して素通しのまま動き続ける（呼び出し側の責務。
//! `Blocklist::load` と同じ形）。
//!
//! 個々の行の parse に失敗しても（壊れた IP、範囲外の prefix 等）panic せず、
//! その行だけを無視して読み進める（PK-54）。

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// IPv4 または IPv6 の CIDR。単体 IP は `/32`（IPv4）か `/128`（IPv6）として持つ。
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

/// `line` を1つの `Cidr` へ parse する。`#` 行・空行・不正な IP・範囲外の
/// prefix（`/999` 等）は `None`（呼び出し側が読み飛ばす）。
fn parse_line(line: &str) -> Option<Cidr> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let (addr_part, prefix_part) = match line.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (line, None),
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

/// `--iplist` に当たる IP/CIDR の集合。
#[derive(Debug, Default, Clone)]
pub struct IpList {
    entries: Vec<Cidr>,
}

#[derive(Debug)]
pub enum IpListError {
    Io(std::io::Error),
}

impl fmt::Display for IpListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(
                f,
                "{}",
                crate::i18n::iplist_io_failed(crate::i18n::locale(), e)
            ),
        }
    }
}

impl std::error::Error for IpListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for IpListError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl IpList {
    /// 何にも当たらない空の iplist（PK-50 の陰性対照）。
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// `path` から iplist を読む。
    pub fn load(path: &Path) -> Result<Self, IpListError> {
        let content = std::fs::read_to_string(path)?;
        let list = Self::parse(&content);
        eprintln!(
            "packetdeath: [info] {}",
            crate::i18n::iplist_loaded(crate::i18n::locale(), path.display(), list.len())
        );
        Ok(list)
    }

    /// `paths` の各 file を [`load`](Self::load) で読む（`--iplist` の複数指定）。
    /// 読めなかった file は `[warn]` を出して空の list にする（fail-open）。
    /// 空の list も返すので、後から file が現れても同じ path で読み直せる。
    pub fn load_all(paths: &[PathBuf]) -> Vec<(PathBuf, Self)> {
        paths
            .iter()
            .map(|path| {
                let list = match Self::load(path) {
                    Ok(list) => list,
                    Err(e) => {
                        eprintln!(
                            "packetdeath: [warn] {}",
                            crate::i18n::iplist_load_failed_empty(
                                crate::i18n::locale(),
                                path.display(),
                                e
                            )
                        );
                        Self::empty()
                    }
                };
                (path.clone(), list)
            })
            .collect()
    }

    /// `lists` の和集合。
    pub fn union<'a>(lists: impl IntoIterator<Item = &'a IpList>) -> Self {
        let entries = lists
            .into_iter()
            .flat_map(|list| list.entries.iter().copied())
            .collect();
        Self { entries }
    }

    /// 登録済み entry の数。reload 前後の差分を log に出すためだけに使う。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// clippy `len_without_is_empty` を満たすための対。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 1行1 IP か CIDR、`#` で始まる行は無視する形式を読む。
    /// 個々の行の parse 失敗は無視して読み進める（panic しない。PK-54）。
    pub fn parse(content: &str) -> Self {
        let mut entries = Vec::new();
        let mut skipped = 0usize;
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match parse_line(line) {
                Some(cidr) => entries.push(cidr),
                None => {
                    skipped += 1;
                    eprintln!(
                        "packetdeath: [warn] {}",
                        crate::i18n::iplist_line_skipped(crate::i18n::locale(), i + 1)
                    );
                }
            }
        }
        eprintln!(
            "packetdeath: [info] {}",
            crate::i18n::iplist_parsed(crate::i18n::locale(), entries.len(), skipped)
        );
        Self { entries }
    }

    /// `ip` が iplist に当たるか。
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.entries.iter().any(|cidr| cidr.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn empty_iplist_matches_nothing() {
        let list = IpList::empty();
        assert!(!list.contains(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn parse_ignores_comment_and_blank_lines() {
        let list = IpList::parse("# comment\n\n93.184.216.34\n  # indented\n");
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn single_ip_matches_exactly() {
        let list = IpList::parse("93.184.216.34\n");
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!list.contains(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))));
    }

    #[test]
    fn cidr_boundary_is_correct_v4() {
        // PK-55: 10.0.0.0/8 に 10.255.255.255 は当たり、11.0.0.0 は当たらない。
        let list = IpList::parse("10.0.0.0/8\n");
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        assert!(!list.contains(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));
    }

    #[test]
    fn cidr_slash_32_matches_single_host_only() {
        let list = IpList::parse("192.0.2.10/32\n");
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
        assert!(!list.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))));
    }

    #[test]
    fn cidr_slash_0_matches_everything_v4() {
        let list = IpList::parse("0.0.0.0/0\n");
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn cidr_boundary_is_correct_v6() -> Result<(), String> {
        let list = IpList::parse("2001:db8::/32\n");
        let in_range: IpAddr = "2001:db8::1".parse().map_err(|e| format!("{e}"))?;
        let range_end: IpAddr = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
            .parse()
            .map_err(|e| format!("{e}"))?;
        let out_of_range: IpAddr = "2001:db9::1".parse().map_err(|e| format!("{e}"))?;
        assert!(list.contains(&in_range));
        assert!(list.contains(&range_end));
        assert!(!list.contains(&out_of_range));
        Ok(())
    }

    #[test]
    fn cidr_slash_128_and_slash_0_v6() {
        let host = IpList::parse("::1/128\n");
        assert!(host.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!host.contains(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        let all = IpList::parse("::/0\n");
        assert!(all.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn v4_and_v6_do_not_cross_match() {
        let list = IpList::parse("10.0.0.0/8\n");
        assert!(!list.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn malformed_lines_are_skipped_without_panicking() {
        // PK-54: 空、# だけ、不正な IP、不正な CIDR、巨大な行、非 ASCII、
        // 範囲外 prefix のいずれも panic せず、有効な行だけが効く。
        let huge_line = "x".repeat(1_000_000);
        let content = format!(
            "\n#\nnot-an-ip\n10.0.0.0/999\n10.0.0.0/abc\n{huge_line}\n日本語\n10.0.0.0/8\n"
        );
        let list = IpList::parse(&content);
        assert!(list.contains(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!list.contains(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));
    }

    #[test]
    fn union_matches_what_either_side_matches() {
        let x = IpList::parse("192.0.2.1\n");
        let y = IpList::parse("10.0.0.0/8\n");
        let both = IpList::union([&x, &y]);
        assert!(both.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(both.contains(&IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))));
        assert!(!both.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn len_counts_entries_and_skips_bad_lines() {
        let list = IpList::parse("192.0.2.1\nnot-an-ip\n# c\n198.51.100.0/24\n");
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        assert!(IpList::empty().is_empty());
    }

    #[test]
    fn load_all_keeps_a_slot_for_an_unreadable_file() {
        let missing = PathBuf::from("/nonexistent/packetdeath-iplist-load-all.txt");
        let loaded = IpList::load_all(std::slice::from_ref(&missing));
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, missing);
        assert!(loaded[0].1.is_empty());
    }

    #[test]
    fn load_missing_file_returns_err() {
        let path = Path::new("/nonexistent/packetdeath-iplist-test.txt");
        assert!(IpList::load(path).is_err());
    }
}
