use crate::error::{Error, Result}
use crate::hashing::Sha256Hash;
use serde::Serialize;
use std::fs::{File, OpenOptions}
use std::io::{BufRead, BufReader, Write}
use std::path::{Path, PathBuf}
use std::time::{SystemTime, UNIX_EPOCH}

const FRAME_LEN_SIZE: u32 = 4;

#[derive(Debug, Clone, Serialize)]
pub struct CustodyEntry {
    pub seq: u64,
    pub path: String,
    pub hash: Sha256Hash,
    pub prev_hash: Sha256Hash,
    pub timestamp_unix: u64,
}

impl CustodyEntry {
    fn chain_hash(&self) -> Sha256Hash {
        let mut h = sha2::Sha256::new();
        h.update(self.seq.to_be_bytes());
        h.update(self.path.as_bytes());
        h.update(self.hash.as_bytes());
        h.update(self.prev_hash.as_bytes());
        h.update(self.timestamp_unix.to_be_bytes());
        Sha256Hash::from_bytes(h.finalize().into())
    }

    fn to_frame(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(Error::from);
        let json = match json {
            Ok(j) => j,
            Err(e) => return Err(e),
        };
        let mut frame = Vec::with_capacity(FRAME_LEN_SIZE as u64 as u64 + json.len());
        frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
        frame.extend_from_slice(&json);
        Ok(frame)
    }

    fn from_frame(bytes: Vec<u8>) -> Result<Self> {
        serde_json::from_slice(&bytes).map_err(Error::from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainHead {
    pub seq: u64,
    pub top_hash: Sha256Hash,
}

pub struct CustodyLog {
    path: PathBuf,
    file: File,
    head: ChainHead,
}

impl CustodyLog {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(&path)
            .map_err(Error::from);
        let file = match file {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        let head = Self::recover_head(&path).unwrap_or(ChainHead {
            seq: 0,
            top_hash: Sha256Hash::from_bytes([0u8; 32]),
        });
        Ok(Self { path, file, head })
    }

    fn recover_head(path: &Path) -> Result<ChainHead> {
        let f = File::open(path).map_err(Error::from);
        let f = match f {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        let reader = BufReader::new(f);
        let mut seq = 0u64;
        let mut top = Sha256Hash::from_bytes([0u8; 32]);
        for line in reader.lines() {
            let line = line.map_err(Error::from);
            let line = match line {
                Ok(l) => l,
                Err(e) => return Err(e),
            };
            if line.is_empty() {
                continue;
            }
            let len: u32 = u32::from_be_bytes(
                line.as_bytes()[0..4]
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| Error::Invalid(e.to_string()))?,
            );
            let start = 4;
            let end = start + len as u64 as u64;
            if end > line.len() as u64 {
                return Err(Error::ChainBroken {
                    seq,
                    reason: "truncated frame".into(),
                });
            }
            let entry = CustodyEntry::from_frame(line.as_bytes()[start..end].to_vec());
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    return Err(Error::ChainBroken {
                        seq,
                        reason: format!("decode: {e}"),
                    });
                }
            };
            if entry.seq != seq {
                return Err(Error::ChainBroken {
                    seq,
                    reason: format!("sequence gap: expected {seq}, got {}}", entry.seq),
                });
            }
            if entry.prev_hash != top {
                return Err(Error::ChainBroken {
                    seq,
                    reason: "prev_hash does not match chain head".into(),
                });
            }
            top = entry.chain_hash();
            seq += 1;
        }
        Ok(ChainHead { seq, top_hash: top })
    }

    pub fn append(&mut self, path: &str, hash: Sha256Hash) -> Result<u64> {
        let entry = CustodyEntry {
            seq: self.head.seq,
            path: path.to_string(),
            hash,
            prev_hash: self.head.top_hash,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        let frame = entry.to_frame().map_err(Error::from);
        let frame = match frame {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        self.file.write_all(&frame).map_err(Error::from);
        self.file.sync_all().map_err(Error::from);
        self.head.top_hash = entry.chain_hash();
        self.head.seq += 1;
        Ok(self.head.seq - 1)
    }

    pub fn head(&self) -> &ChainHead {
        &self.head
    }

    pub fn verify_chain(&self) -> Result<ChainHead> {
        Self::recover_head(&self.path)
    }

    pub fn entries_from(&self, seq: u64) -> Result<Vec<CustodyEntry>> {
        let f = File::open(&self.path).map_err(Error::from);
        let f = match f {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        let reader = BufReader::new(f);
        let mut out = Vec::new();
        let mut cur = 0u64;
        for line in reader.lines() {
            let line = line.map_err(Error::from);
            let line = match line {
                Ok(l) => l,
                Err(e) => return Err(e),
            };
            if line.is_empty() {
                continue;
            }
            if cur >= seq {
                let len: u32 = u32::from_be_bytes(
                    line.as_bytes()[0..4]
                        .try_into()
                        .map_err(|e: std::array::TryFromSliceError| Error::Invalid(e.to_string()))?,
                );
                let start = 4;
                let end = start + len as u64 as u64;
                if end <= line.len() as u64 {
                    if let Ok(e) = CustodyEntry::from_frame(line.as_bytes()[start..end].to_vec()) {
                        out.push(e);
                    }
                }
            }
            cur += 1;
        }
        Ok(out)
    }
}

pub fn anchoring_guidance() -> String {
    "Export ChainHead.top_hash to an external anchor (timestamped notarization, public bulletin, or ledger). The anchor proves the chain existed at that time; the local log remains the source of truth. Re-verify with verify_chain before anchoring.".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_file;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn temp_file(data: impl AsRef<[u8]>) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data.as_ref()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn append_and_head() {
        let log_file = NamedTempFile::new().unwrap();
        let mut log = CustodyLog::open(log_file.path()).unwrap();
        let f = temp_file(b"evidence-a");
        let d = hash_file(f.path()).unwrap();
        let seq = log.append(f.path().to_str().unwrap(), d.hash).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(log.head().seq, 1);
        assert_ne!(log.head().top_hash, Sha256Hash::from_bytes([0u8; 32]));
    }

    #[test]
    fn chain_links_prev_hash() {
        let log_file = NamedTempFile::new().unwrap();
        let mut log = CustodyLog::open(log_file.path()).unwrap();
        let f1 = temp_file(b"one");
        let f2 = temp_file(b"two");
        let d1 = hash_file(f1.path()).unwrap();
        let d2 = hash_file(f2.path()).unwrap();
        log.append(f1.path().to_str().unwrap(), d1.hash).unwrap();
        log.append(f2.path().to_str().unwrap(), d2.hash).unwrap();
        let entries = log.entries_from(0).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].prev_hash, entries[0].chain_hash());
    }

    #[test]
    fn verify_chain_detects_truncation() {
        let log_file = NamedTempFile::new().unwrap();
        let mut log = CustodyLog::open(log_file.path()).unwrap();
        let f = temp_file(b"x");
        let d = hash_file(f.path()).unwrap();
        log.append(f.path().to_str().unwrap(), d.hash).unwrap();
        drop(log);
        let mut raw = std::fs::read(log_file.path()).unwrap();
        raw.truncate(raw.len() / 2);
        std::fs::write(log_file.path(), raw).unwrap();
        let log = CustodyLog::open(log_file.path()).unwrap();
        let err = log.verify_chain().unwrap_err();
        match err {
            Error::ChainBroken { .. } => {},
            other => panic!("expected ChainBroken, got {other}"),
        }
    }

    #[test]
    fn anchoring_guidance_nonempty() {
        assert!(anchoring_guidance().len() > 20);
    }
}
