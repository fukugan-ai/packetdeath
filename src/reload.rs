//! poll loop の中で、稼働中に書き換えられる file（blocklist / allowlist）を
//! 安全に読み直すための共通部品。`block_loop::run_watch_loop` が
//! `WatchInputs` 経由で使う。
//!
//! # 検知の方法（判断）
//!
//! **`mtime` と `len` の組を「指紋」として使う。**file 全体の hash も候補に
//! 挙がったが（47,677 行で 26 ms。file を丸ごと読む必要が在る）、
//! `metadata()` だけで済む mtime+len の方が安く、`block_loop::run_watch_loop`
//! が pcapng の再読み込み要否を `len()` で判定しているのと同じ発想を
//! 踏襲できる。`mtime` 単独は file system によっては秒単位の解像度しか
//! 持たず、1秒未満の連続した書き換えを取りこぼす。`len` を組にすることで、
//! 同じ mtime 内の書き換え（byte 数が変わる編集）も捕まえられる。それでも
//! 取りこぼした場合は fail-open（前の内容を使い続けるだけ）であり、実害は
//! 次の poll まで遅れるだけである。
//!
//! # 書き換え途中を読む危険をどう塞いだか
//!
//! **読み込みの直前と直後、両方で指紋を取り、一致したときだけ採用する。**
//! 一致しなければ、書き込み側がまだ書いている最中に読んだ可能性が在るので、
//! この poll では読み直しを諦め（`ReloadOutcome::Unchanged` を返す。log は
//! 出さない ── 次の poll で自然に収束する一時的な事象であり、warn にすると
//! 継続的な書き込みのたびに log が溢れる）、次の poll で改めて指紋を
//! 比較する。file が消えた・読めない場合は 1 回だけ `Failed` を返し、
//! 以後 状態が変わらない限り `Unchanged` を返し続ける（log が溢れない）。

use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    modified: SystemTime,
    len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileState {
    Present(Fingerprint),
    Missing,
}

fn current_state(path: &Path) -> FileState {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok().map(|modified| (modified, m.len())))
        .map(|(modified, len)| FileState::Present(Fingerprint { modified, len }))
        .unwrap_or(FileState::Missing)
}

/// 1回の [`ReloadWatcher::poll`] の結果。
pub enum ReloadOutcome {
    /// 前回と変化が無い。呼び出し側は何もしない（log も出さない）。
    Unchanged,
    /// 新しい内容を読めた。呼び出し側は値を作り直して差し替える。
    Loaded(String),
    /// file が読めなかった（消失・権限・不正 UTF-8 等）。呼び出し側は
    /// 前の値を使い続ける（fail-open）。
    Failed(String),
}

/// `path` を poll ごとに監視し、変化を検知したら読み直す。
pub struct ReloadWatcher {
    path: PathBuf,
    state: FileState,
}

impl ReloadWatcher {
    /// `path` の現在の状態を初期値として覚える。construct 直後に
    /// [`poll`](Self::poll) を呼んでも、construct 時から変化が無ければ
    /// `Unchanged` になる。
    pub fn new(path: PathBuf) -> Self {
        let state = current_state(&path);
        Self { path, state }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 1回の poll 分の判定。
    pub fn poll(&mut self) -> ReloadOutcome {
        let before = current_state(&self.path);
        if before == self.state {
            return ReloadOutcome::Unchanged;
        }
        if before == FileState::Missing {
            self.state = FileState::Missing;
            return ReloadOutcome::Failed(crate::i18n::reload_file_not_found(
                crate::i18n::locale(),
                self.path.display(),
            ));
        }
        match std::fs::read_to_string(&self.path) {
            Ok(content) => {
                let after = current_state(&self.path);
                if after != before {
                    // 読んでいる間に書き換えが進行していた。state は更新せず、
                    // 次の poll で改めて判定する（今回は静かに諦める）。
                    return ReloadOutcome::Unchanged;
                }
                self.state = after;
                ReloadOutcome::Loaded(content)
            }
            Err(e) => {
                self.state = before;
                ReloadOutcome::Failed(crate::i18n::reload_file_read_failed(
                    crate::i18n::locale(),
                    self.path.display(),
                    e,
                ))
            }
        }
    }
}

/// `watcher` が変化を検知したら `parse` で新しい値を作って `current` を
/// 差し替え、`[info]`／`[warn]` を1行 出す。変化が無ければ何もしない
/// （log も出さない。poll ごとに出すと log が溢れるため）。
///
/// `parse` は `Blocklist::parse` / `Allowlist::parse` のように infallible
/// （構文エラーの行を無視するだけで必ず値を返す）である前提。読み込み自体の
/// 失敗（file 消失・IO error・不正 UTF-8）は [`ReloadWatcher::poll`] 側で
/// `Failed` として捕まっており、ここまで来ない。
///
/// `current` を差し替えたときだけ `true` を返す（複数 file の和集合を
/// 組み直す要否を呼び出し側が知るため）。
pub fn apply<T>(
    watcher: &mut ReloadWatcher,
    current: &mut T,
    kind: &str,
    parse: impl Fn(&str) -> T,
    len_of: impl Fn(&T) -> usize,
) -> bool {
    match watcher.poll() {
        ReloadOutcome::Unchanged => false,
        ReloadOutcome::Loaded(content) => {
            let before = len_of(current);
            *current = parse(&content);
            let after = len_of(current);
            crate::flow::service_log(&format!(
                "packetdeath: [info] {}",
                crate::i18n::reload_succeeded(
                    crate::i18n::locale(),
                    kind,
                    watcher.path().display(),
                    after,
                    before,
                )
            ));
            true
        }
        ReloadOutcome::Failed(msg) => {
            crate::flow::service_log(&format!(
                "packetdeath: [warn] {}",
                crate::i18n::reload_failed(crate::i18n::locale(), kind, msg)
            ));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::Blocklist;
    use std::time::Duration;

    fn unique_path(name: &str) -> Result<PathBuf, String> {
        let dir = std::env::temp_dir().join(format!(
            "packetdeath-reload-unit-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(dir.join("list.txt"))
    }

    #[test]
    fn unchanged_content_yields_unchanged() -> Result<(), String> {
        let path = unique_path("unchanged")?;
        std::fs::write(&path, "a.example\n").map_err(|e| e.to_string())?;
        let mut watcher = ReloadWatcher::new(path);
        assert!(matches!(watcher.poll(), ReloadOutcome::Unchanged));
        Ok(())
    }

    #[test]
    fn changed_content_yields_loaded() -> Result<(), String> {
        let path = unique_path("changed")?;
        std::fs::write(&path, "a.example\n").map_err(|e| e.to_string())?;
        let mut watcher = ReloadWatcher::new(path.clone());
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, "a.example\nb.example\n").map_err(|e| e.to_string())?;
        match watcher.poll() {
            ReloadOutcome::Loaded(content) => {
                assert_eq!(content, "a.example\nb.example\n");
            }
            _ => return Err("Loaded を期待した".to_string()),
        }
        Ok(())
    }

    #[test]
    fn missing_file_yields_failed_once_then_unchanged() -> Result<(), String> {
        let path = unique_path("missing")?;
        std::fs::write(&path, "a.example\n").map_err(|e| e.to_string())?;
        let mut watcher = ReloadWatcher::new(path.clone());
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        assert!(matches!(watcher.poll(), ReloadOutcome::Failed(_)));
        // 消えたままなら、以降は変化なし（log が溢れない）。
        assert!(matches!(watcher.poll(), ReloadOutcome::Unchanged));
        Ok(())
    }

    #[test]
    fn apply_keeps_previous_value_on_missing_file() -> Result<(), String> {
        let path = unique_path("apply-missing")?;
        std::fs::write(&path, "kept.example\n").map_err(|e| e.to_string())?;
        let mut watcher = ReloadWatcher::new(path.clone());
        let mut blocklist = Blocklist::parse("kept.example\n");

        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        apply(
            &mut watcher,
            &mut blocklist,
            "blocklist",
            Blocklist::parse,
            Blocklist::len,
        );

        assert!(blocklist.matches("kept.example"));
        Ok(())
    }

    #[test]
    fn apply_replaces_value_on_change() -> Result<(), String> {
        let path = unique_path("apply-changed")?;
        std::fs::write(&path, "old.example\n").map_err(|e| e.to_string())?;
        let mut watcher = ReloadWatcher::new(path.clone());
        let mut blocklist = Blocklist::parse("old.example\n");

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, "new.example\n").map_err(|e| e.to_string())?;
        apply(
            &mut watcher,
            &mut blocklist,
            "blocklist",
            Blocklist::parse,
            Blocklist::len,
        );

        assert!(blocklist.matches("new.example"));
        assert!(!blocklist.matches("old.example"));
        Ok(())
    }
}
