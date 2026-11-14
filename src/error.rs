//! Error type shared by all modules.

use crate::hashing::Sha256Hash;
use std::fmt;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

/// One file whose current bytes do not match the trusted hash.
#[derive(Debug, Clone)]
pub struct Mismatch {
    pub path: PathBuf,
    pub expected: Sha256Hash,
    /// `None` means the file is missing or unreadable.
    pub found: Option<Sha256Hash>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// The custody log is broken at `seq`. History was rewritten, reordered or truncated.
    ChainBroken {
        seq: u64,
        reason: String,
    },
    /// Verify-before-trust failed. Every mismatching file is listed, and nothing was exported.
    Mismatch(Vec<Mismatch>),
    /// A file is not in the custody log, so it has no trusted hash to check against.
    NotIngested(String),
    /// Bad input, such as an AI summary that points at an unknown source.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::ChainBroken { seq, reason } => {
                write!(f, "custody chain broken at entry {seq}: {reason}")
            }
            Error::Mismatch(list) => {
                write!(
                    f,
                    "verify-before-trust failed for {} file(s); export stopped",
                    list.len()
                )?;
                for m in list {
                    let found = m
                        .found
                        .map(|h| h.to_hex())
                        .unwrap_or_else(|| "missing".into());
                    write!(
                        f,
                        "\n  {}: expected {}, found {}",
                        m.path.display(),
                        m.expected,
                        found
                    )?;
                }
                Ok(())
            }
            Error::NotIngested(p) => write!(f, "{p} has no custody log entry; ingest it first"),
            Error::Invalid(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}
