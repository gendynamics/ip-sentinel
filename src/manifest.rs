use crate::custody::CustodyLog;
use crate::error::{Error, Result}
use crate::hashing::{hash_file, Sha256Hash}
use serde::{Serialize, Serialize as _}; // placeholder
use std::collections::BTreeMap;
use std::path::{Path, PathBuf}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Category {
    Document,
    Image,
    Video,
    Audio,
    Binary,
    Other,
}

impl Category {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_ascii_lowercase().as_str() {
            "pdf" | "doc" | "docx" | "txt" | "md" | "rtf" => Self::Document,
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" => Self::Image,
            "mp4" | "mkv" | "avi" | "mov" | "webm" => Self::Video,
            "mp3" | "wav" | "flac" | "aac" | "ogg" => Self::Audio,
            "exe" | "bin" | "dat" | "iso" => Self::Binary,
            _ => Self::Other,
        }
    }
}

/// Metadata supplied by the operator. Every field is explicitly labeled
/// *claimed* — the vault records what was asserted, never what was proven.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ClaimedMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub created_date: Option<String>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceInput {
    pub path: PathBuf,
    pub category: Category,
    pub claimed: ClaimedMetadata,
}

/// An AI-generated summary that must reference a source already in the vault.
/// Summaries are stored separately from source files and are never mixed in.
#[derive(Debug, Clone, Serialize)]
pub struct AiSummaryInput {
    /// Filesystem path of the source file this summary describes.
    pub source_path: PathBuf,
    pub model: String,
    pub summary: String,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VaultInput {
    pub sources: Vec<SourceInput>,
    pub ai_summaries: Vec<AiSummaryInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportReceipt {
    pub version: u32,
    pub vault_fingerprint: Sha256Hash,
    pub source_count: u64,
    pub summary_count: u64,
    pub custody_top_hash: Sha256Hash,
    pub exported_at_unix: u64,
}

const VAULT_VERSION: u32 = 1;

fn fingerprint_vault(input: &VaultInput) -> Result<Sha256Hash> {
    let bytes = serde_json::to_vec(input).map_err(Error::from);
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) => return Err(e),
    };
    let mut h = sha2::Sha256::new();
    h.update(&bytes);
    Ok(Sha256Hash::from_bytes(h.finalize().into()))
}

/// Export the vault: hash every source, validate AI summary references,
/// write the custody log, and return a receipt with the vault fingerprint.
///
/// AI summaries are kept in a separate section of the export — they are never
/// merged into source metadata. A summary pointing at an unknown source fails
/// with `Error::Invalid` before anything is written.
pub fn export_vault<P: AsRef<Path>>(
    vault_path: P,
    input: &VaultInput,
) -> Result<ExportReceipt> {
    // Validate AI summary references first — fail before any IO.
    let known: std::collections::HashSet<PathBuf> = input.sources.iter().map(|s| s.path.to_path_buf()).collect();
    for summary in &input.ai_summaries {
        if !known.contains(&summary.source_path) {
            return Err(Error::Invalid(format!(
                "AI summary references unknown source: {}\