use crate::error::{Error, Result};
use crate::hashing::Sha256Hash;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Big-endian length prefix in front of each JSON custody frame.
const FRAME_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub seq: u64,
    pub path: String,
    pub hash: Sha256Hash,
    pub prev_hash: Sha256Hash,
    pub timestamp_unix: u64,
}

/// Name re-exported by the crate root.
pub type Entry = CustodyEntry;

impl CustodyEntry {
    fn chain_hash(&self) -> Sha256Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.seq.to_be_bytes());
        hasher.update(self.path.as_bytes());
        hasher.update(self.hash.as_bytes());
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(self.timestamp_unix.to_be_bytes());
        Sha256Hash::from_bytes(hasher.finalize().into())
    }

    fn to_frame(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self)?;
        let len = u32::try_from(json.len())
            .map_err(|_| Error::Invalid("custody entry exceeds 4 GiB".into()))?;
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + json.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&json);
        Ok(frame)
    }

    fn from_frame(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
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
            .create(true)
            .append(true)
            .open(&path)?;
        // A broken log still opens. `verify_chain` reports the damage; replacing
        // the head here is what lets a caller inspect a truncated file.
        let head = Self::recover_head(&path).unwrap_or(ChainHead {
            seq: 0,
            top_hash: Sha256Hash::from_bytes([0u8; 32]),
        });
        Ok(Self { path, file, head })
    }

    fn recover_head(path: &Path) -> Result<ChainHead> {
        let entries = Self::read_entries(path)?;
        Self::validate_chain(&entries)
    }

    fn read_entries(path: &Path) -> Result<Vec<CustodyEntry>> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut pos = 0u64;
        let mut entries = Vec::new();

        loop {
            if pos == file_len {
                return Ok(entries);
            }
            let seq = entries.len() as u64;
            if file_len - pos < FRAME_HEADER_LEN as u64 {
                return Err(Error::ChainBroken {
                    seq,
                    reason: "truncated frame".into(),
                });
            }
            let mut len_buf = [0u8; FRAME_HEADER_LEN];
            file.read_exact(&mut len_buf)
                .map_err(|err| map_read_err(err, seq))?;
            pos += FRAME_HEADER_LEN as u64;
            let len = u64::from(u32::from_be_bytes(len_buf));
            if file_len - pos < len {
                return Err(Error::ChainBroken {
                    seq,
                    reason: "truncated frame".into(),
                });
            }
            let mut body = vec![0u8; len as usize];
            file.read_exact(&mut body)
                .map_err(|err| map_read_err(err, seq))?;
            pos += len;
            let entry = CustodyEntry::from_frame(&body).map_err(|err| Error::ChainBroken {
                seq,
                reason: format!("decode: {err}"),
            })?;
            entries.push(entry);
        }
    }

    fn validate_chain(entries: &[CustodyEntry]) -> Result<ChainHead> {
        let mut seq = 0u64;
        let mut top = Sha256Hash::from_bytes([0u8; 32]);
        for entry in entries {
            if entry.seq != seq {
                return Err(Error::ChainBroken {
                    seq,
                    reason: format!("sequence gap: expected {seq}, got {}", entry.seq),
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
        let frame = entry.to_frame()?;
        self.file.write_all(&frame)?;
        self.file.sync_all()?;
        let assigned = entry.seq;
        self.head.top_hash = entry.chain_hash();
        self.head.seq += 1;
        Ok(assigned)
    }

    pub fn head(&self) -> &ChainHead {
        &self.head
    }

    pub fn verify_chain(&self) -> Result<ChainHead> {
        Self::recover_head(&self.path)
    }

    pub fn entries_from(&self, seq: u64) -> Result<Vec<CustodyEntry>> {
        let entries = Self::read_entries(&self.path)?;
        Ok(entries
            .into_iter()
            .filter(|entry| entry.seq >= seq)
            .collect())
    }
}

fn map_read_err(err: std::io::Error, seq: u64) -> Error {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::ChainBroken {
            seq,
            reason: "truncated frame".into(),
        }
    } else {
        Error::Io(err)
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
            Error::ChainBroken { .. } => {}
            other => panic!("expected ChainBroken, got {other}"),
        }
    }

    #[test]
    fn anchoring_guidance_nonempty() {
        assert!(anchoring_guidance().len() > 20);
    }
}
