//! # ip-sentinel-core
//!
//! Local-only cryptographic engine for the IP Sentinel skill. This crate makes no
//! network calls and uses no credentials.
//!
//! - [`hashing`]: SHA-256 file hashing, plus a verify-before-trust check that re-hashes
//!   files and stops on any mismatch.
//! - [`custody`]: a hash-chained, append-only custody log and its top hash for outside
//!   anchoring.
//! - [`manifest`]: a timeline-ordered, SHA-256-fingerprinted evidence vault index.
//!   Every metadata field is labeled as claimed and not verified, and AI summaries are
//!   kept separate from source files.
pub mod custody;
pub mod error;
pub mod hashing;
pub mod manifest;

pub use custody::{anchoring_guidance, ChainHead, CustodyLog, Entry};
pub use error::{Error, Mismatch, Result};
pub use hashing::{hash_file, verify_before_trust, FileDigest, Sha256Hash};
pub use manifest::{
    export_vault, verify_vault, AiSummaryInput, Category, ClaimedMetadata, ExportReceipt,
    SourceInput, VaultInput,
};
