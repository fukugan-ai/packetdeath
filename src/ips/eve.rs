//! Stage 12: a bounded reader for `eve.json`. `docs/design.md`
//! "段階12 IDS/IPS の業務水準化".
//!
//! One `read` takes at most `max_read` bytes, so a flood after a Suricata
//! restart is worked off over several polls instead of filling memory. A line
//! longer than `max_line` is skipped and counted. A rename-style rotation is
//! seen from the inode and the first bytes of the file; a copytruncate from a
//! file shorter than the offset. Both start the new file from its first byte.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const HEAD: usize = 64;

/// What one `read` found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Batch {
    /// Complete lines, valid UTF-8, without the newline.
    pub lines: Vec<String>,
    /// Lines longer than the limit, skipped.
    pub oversized: usize,
    /// Lines that are not UTF-8, skipped.
    pub bad_utf8: usize,
    /// The file is a new file or was truncated; reading restarted at byte 0.
    pub restarted: bool,
    /// Bytes remain; the next poll continues.
    pub more: bool,
}

/// Where the reader stands in one file.
#[derive(Debug, Default)]
pub struct EveReader {
    offset: u64,
    inode: u64,
    head: Vec<u8>,
    skipping: bool,
}

#[cfg(unix)]
fn inode_of(file: &File) -> Result<u64, String> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().map(|m| m.ino()).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn inode_of(_file: &File) -> Result<u64, String> {
    Ok(0)
}

fn read_head(file: &mut File) -> Result<Vec<u8>, String> {
    let mut head = vec![0_u8; HEAD];
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut got = 0;
    while got < HEAD {
        let n = file.read(&mut head[got..]).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        got += n;
    }
    head.truncate(got);
    Ok(head)
}

impl EveReader {
    pub fn new() -> Self {
        Self::default()
    }

    fn restart(&mut self, inode: u64, head: Vec<u8>) {
        self.offset = 0;
        self.inode = inode;
        self.head = head;
        self.skipping = false;
    }

    /// Read the next bounded piece of `path`.
    pub fn read(&mut self, path: &Path, max_read: usize, max_line: usize) -> Result<Batch, String> {
        let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        let inode = inode_of(&file)?;
        let head = read_head(&mut file)?;
        let mut batch = Batch::default();
        let same_file = inode == self.inode && head.starts_with(&self.head);
        if (self.offset > 0 || !self.head.is_empty()) && (!same_file || len < self.offset) {
            batch.restarted = true;
            self.restart(inode, head.clone());
        }
        if head.len() > self.head.len() {
            self.head = head;
        }
        self.inode = inode;
        // A window of two line limits always holds a newline or an oversized
        // tail, so a poll can never stall on a line that does not fit.
        let window = max_read.max(max_line.saturating_mul(2)) as u64;
        let room = len.saturating_sub(self.offset).min(window);
        file.seek(SeekFrom::Start(self.offset)).map_err(|e| e.to_string())?;
        let mut buf = vec![0_u8; room as usize];
        file.read_exact(&mut buf).map_err(|e| e.to_string())?;
        batch.more = self.offset + room < len;
        self.split(&buf, max_line, &mut batch);
        Ok(batch)
    }

    fn split(&mut self, buf: &[u8], max_line: usize, batch: &mut Batch) {
        let mut start = 0;
        while start < buf.len() {
            let Some(end) = buf[start..].iter().position(|b| *b == b'\n') else {
                let tail = buf.len() - start;
                if self.skipping || tail > max_line {
                    if !self.skipping {
                        batch.oversized += 1;
                    }
                    self.skipping = true;
                    self.offset += tail as u64;
                }
                return;
            };
            let line = &buf[start..start + end];
            self.offset += end as u64 + 1;
            start += end + 1;
            if self.skipping {
                self.skipping = false;
            } else if line.len() > max_line {
                batch.oversized += 1;
            } else if let Ok(text) = std::str::from_utf8(line) {
                batch.lines.push(text.to_owned());
            } else {
                batch.bad_utf8 += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("ips-test")
            .join(format!("eve-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join(name))
    }

    #[test]
    fn appended_lines_are_read_once_and_a_half_line_waits() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("append.json")?;
        std::fs::write(&path, "one\ntwo\nthr")?;
        let mut r = EveReader::new();
        assert_eq!(r.read(&path, 1024, 100)?.lines, vec!["one", "two"]);
        std::fs::write(&path, "one\ntwo\nthree\n")?;
        let again = r.read(&path, 1024, 100)?;
        assert_eq!((again.lines, again.restarted), (vec![String::from("three")], false));
        assert!(r.read(&path, 1024, 100)?.lines.is_empty());
        Ok(())
    }

    #[test]
    fn a_poll_takes_at_most_max_read_and_the_rest_comes_next() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("flood.json")?;
        std::fs::write(&path, "aaaa\n".repeat(10))?;
        let mut r = EveReader::new();
        let first = r.read(&path, 10, 5)?;
        assert_eq!((first.lines.len(), first.more), (2, true));
        let mut total = first.lines.len();
        while r.read(&path, 10, 5).map(|b| { total += b.lines.len(); b.more })? {}
        assert_eq!(total, 10);
        Ok(())
    }

    #[test]
    fn a_line_over_the_limit_is_skipped_even_when_it_spans_polls() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("long.json")?;
        let body = format!("ok\n{}\nafter\n", "x".repeat(300));
        std::fs::write(&path, body)?;
        let mut r = EveReader::new();
        let (mut lines, mut oversized) = (Vec::new(), 0);
        loop {
            let b = r.read(&path, 64, 100)?;
            lines.extend(b.lines);
            oversized += b.oversized;
            if !b.more {
                break;
            }
        }
        assert_eq!((lines, oversized), (vec![String::from("ok"), String::from("after")], 1));
        Ok(())
    }

    #[test]
    fn bad_utf8_is_dropped_not_repaired() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("utf8.json")?;
        std::fs::write(&path, b"good\n\xff\xfe\nlast\n")?;
        let b = EveReader::new().read(&path, 1024, 100)?;
        assert_eq!((b.lines, b.bad_utf8), (vec![String::from("good"), String::from("last")], 1));
        Ok(())
    }

    #[test]
    fn a_renamed_rotation_and_a_truncation_both_restart_at_byte_zero() -> Result<(), Box<dyn std::error::Error>> {
        let path = scratch("rotate.json")?;
        std::fs::write(&path, "old-line-1\nold-line-2\n")?;
        let mut r = EveReader::new();
        r.read(&path, 1024, 100)?;
        let moved = scratch("rotate.json.1")?;
        std::fs::rename(&path, &moved)?;
        std::fs::write(&path, "new-line-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")?;
        let b = r.read(&path, 1024, 100)?;
        assert_eq!((b.restarted, b.lines.len()), (true, 1));
        std::fs::write(&path, "z\n")?;
        let t = r.read(&path, 1024, 100)?;
        assert_eq!((t.restarted, t.lines), (true, vec![String::from("z")]));
        Ok(())
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let gone = Path::new("/nonexistent-eve-9f3a/eve.json");
        assert!(EveReader::new().read(gone, 10, 10).is_err());
    }
}
