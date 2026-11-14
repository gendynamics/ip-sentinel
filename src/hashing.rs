use crate::error::{Error, Mismatch, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

/// A SHA-256 digest, stored as raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::Invalid(format!("bad hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::Invalid(format!(
                "expected 32 bytes, got {} from hex string",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl Serialize for Sha256Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Self::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

/// Result of hashing a single file: its path and digest.
#[derive(Debug, Clone)]
pub struct FileDigest {
    pub path: PathBuf,
    pub hash: Sha256Hash,
}

/// Hash a file at `path` with SHA-256. Streams in 64 KiB chunks so large
/// files don't load into memory.
pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<FileDigest> {
    let path = path.as_ref().to_path_buf();
    let file = File::open(&path).map_err(Error::Io);
    let file = match file {
        Ok(f) => f,
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(Error::Io);
        let n = match n {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
    }
    Ok(FileDigest {
        path,
        hash: Sha256Hash(hasher.finalize().into()),
    })
}

/// Re-hash every path and compare against the trusted digests.
///
/// On any mismatch the function returns `Error::Mismatch` listing **all**
/// mismatches found (it does not stop at the first) and nothing is exported.
/// Files that are missing or unreadable appear with `found: None`.
pub fn verify_before_trust(trusted: &[(PathBuf, Sha256Hash)]) -> Result<Vec<FileDigest>> {
    let mut results = Vec::with_capacity(trusted.len());
    let mut mismatches = Vec::new();

    for (path, expected) in trusted {
        match hash_file(path) {
            Ok(digest) => {
                if digest.hash != *expected {
                    mismatches.push(Mismatch {
                        path: path.to_path_buf(),
                        expected: *expected,
                        found: Some(digest.hash),
                    });
                }
                results.push(digest);
            }
            Err(_) => {
                mismatches.push(Mismatch {
                    path: path.to_path_buf(),
                    expected: *expected,
                    found: None,
                });
            }
        }
    }

    if mismatches.is_empty() {
        Ok(results)
    } else {
        Err(Error::Mismatch(mismatches))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(data: impl AsRef<[u8]>) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(data.as_ref()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn hash_file_is_deterministic() {
        let f = write_temp(b"ip-sentinel-test-payload");
        let a = hash_file(f.path()).unwrap();
        let b = hash_file(f.path()).unwrap();
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.path, f.path());
    }

    #[test]
    fn hash_file_differs_for_different_content() {
        let a = hash_file(write_temp(b"alpha").path()).unwrap();
        let b = hash_file(write_temp(b"beta").path()).unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn verify_before_trust_passes_on_match() {
        let f = write_temp(b"stable-bytes");
        let digest = hash_file(f.path()).unwrap();
        let out = verify_before_trust(&[(f.path().to_path_buf(), digest.hash)]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].hash, digest.hash);
    }

    #[test]
    fn verify_before_trust_reports_all_mismatches() {
        let f1 = write_temp(b"v1");
        let f2 = write_temp(b"v2");
        let d1 = hash_file(f1.path()).unwrap();
        // Tamper: write different bytes to f1 after hashing.
        std::fs::write(f1.path(), b"TAMPERED").unwrap();
        let d2 = hash_file(f2.path()).unwrap();
        // Give f2 a wrong expected hash too.
        let bad = Sha256Hash::from_hex(&"00".repeat(32)).unwrap_or_else(|_| {
            // fallback: just flip a byte of a real hash
            let mut h = d2.hash.as_bytes();
            h[0] ^= 0xff;
            Sha256Hash::from_bytes(h)
        });
        let err = verify_before_trust(&[
            (f1.path().to_path_buf(), d1.hash),
            (f2.path().to_path_buf(), bad),
        ])
        .unwrap_err();
        match err {
            Error::Mismatch(list) => assert_eq!(list.len(), 2),
            other => panic!("expected Mismatch, got {other}"),
        }
    }

    #[test]
    fn verify_before_trust_missing_file() {
        let missing = PathBuf::from("/tmp/ip-sentinel-does-not-exist-xyz");
        let err = verify_before_trust(&[(missing, Sha256Hash::from_bytes([0u8; 32]))]).unwrap_err();
        match err {
            Error::Mismatch(list) => {
                assert_eq!(list.len(), 1);
                assert!(list[0].found.is_none());
            }
            other => panic!("expected Mismatch, got {other}"),
        }
    }

    #[test]
    fn sha256_hex_round_trip() {
        let f = write_temp(b"round-trip");
        let d = hash_file(f.path()).unwrap();
        let restored = Sha256Hash::from_hex(&d.hash.to_hex()).unwrap();
        assert_eq!(restored, d.hash);
    }
}
