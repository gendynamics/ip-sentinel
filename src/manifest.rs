//! Timeline-ordered evidence vault index.
//!
//! Local-only: this module makes no network calls and uses no credentials.
//! The index is built from [`FileDigest`] values stored in a [`CustodyLog`],
//! ordered by custody time and then sequence. Each entry is labeled claimed or
//! verified. `verified` means the content hash was re-checked against the file
//! and the custody chain. Operator-supplied metadata stays claimed.
//!
//! The on-disk export is versioned. `version` is the first JSON field so
//! [`verify_vault`] can read it before interpreting the rest.

use crate::custody::{CustodyEntry, CustodyLog};
use crate::error::{Error, Result};
use crate::hashing::{hash_file, verify_before_trust, FileDigest, Sha256Hash};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Export format version written into [`ExportReceipt`] and the vault index.
const VAULT_VERSION: u32 = 1;

/// Label attached to every [`ClaimedMetadata`] field in its serialized form.
///
/// User-supplied metadata is claimed and never verified. This label is the
/// whole status of those values.
pub const CLAIM_LABEL: &str = "claimed and never verified";

/// Coarse type of a source, derived from its filename extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Category {
    Document,
    Image,
    Video,
    Audio,
    Binary,
    Other,
}

impl Category {
    /// Map a filename extension to a [`Category`].
    ///
    /// The match is case-insensitive. Leading dots are ignored, so `"pdf"` and
    /// `".PDF"` are both [`Category::Document`]. Unknown extensions are
    /// [`Category::Other`].
    pub fn from_extension(ext: &str) -> Self {
        let normalized = ext.trim().trim_start_matches('.').to_ascii_lowercase();
        match normalized.as_str() {
            "pdf" | "doc" | "docx" | "txt" | "md" | "rtf" => Self::Document,
            "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" => Self::Image,
            "mp4" | "mkv" | "avi" | "mov" | "webm" => Self::Video,
            "mp3" | "wav" | "flac" | "aac" | "ogg" => Self::Audio,
            "exe" | "bin" | "dat" | "iso" => Self::Binary,
            _ => Self::Other,
        }
    }
}

/// Operator-supplied description of a source.
///
/// Every field is claimed and never verified. Rechecking a file hash does not
/// change these values, and this struct has no `verified` flag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimedMetadata {
    /// Claimed title. This value is claimed and never verified.
    pub title: Option<String>,
    /// Claimed description. This value is claimed and never verified.
    pub description: Option<String>,
    /// Claimed author. This value is claimed and never verified.
    pub author: Option<String>,
    /// Claimed creation date, as supplied by the operator. Claimed and never verified.
    pub created_date: Option<String>,
    /// Claimed tags. These values are claimed and never verified.
    pub tags: Vec<String>,
    /// Claimed notes. This value is claimed and never verified.
    pub notes: Option<String>,
}

/// Serialized wrapper that labels one claimed value.
struct ClaimedValue<'a, T>(&'a T);

impl<T: Serialize> Serialize for ClaimedValue<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ClaimedValue", 2)?;
        state.serialize_field("label", CLAIM_LABEL)?;
        state.serialize_field("value", self.0)?;
        state.end()
    }
}

impl Serialize for ClaimedMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ClaimedMetadata", 6)?;
        state.serialize_field("title", &ClaimedValue(&self.title))?;
        state.serialize_field("description", &ClaimedValue(&self.description))?;
        state.serialize_field("author", &ClaimedValue(&self.author))?;
        state.serialize_field("created_date", &ClaimedValue(&self.created_date))?;
        state.serialize_field("tags", &ClaimedValue(&self.tags))?;
        state.serialize_field("notes", &ClaimedValue(&self.notes))?;
        state.end()
    }
}

/// Hash assurance for one vault entry.
///
/// [`RecordLabel::Verified`] is allowed only after the content hash has been
/// re-checked against the file bytes and the custody chain. It does not apply
/// to operator-supplied metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordLabel {
    /// Hash taken from the custody log and not yet re-checked against the file.
    Claimed,
    /// Hash re-checked against the file and the custody chain.
    Verified,
}

/// One source file to bring into the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceInput {
    pub path: PathBuf,
    pub category: Category,
    /// Operator assertions about this source. Claimed and never verified.
    pub claimed: ClaimedMetadata,
}

/// An AI-generated summary of a source.
///
/// Summaries are not source files. They reference a source path, live in their
/// own section of the vault, and carry their own content hash via
/// [`AiSummaryInput::content_hash`]. That hash covers the summary text only
/// and is never treated as the source file hash. A summary stays
/// [`RecordLabel::Claimed`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AiSummaryInput {
    /// Filesystem path of the source this summary describes.
    pub source_path: PathBuf,
    /// Name of the model that produced the summary.
    pub model: String,
    /// Summary text. Hashed on its own and not mixed into the source record.
    pub summary: String,
    /// Optional model-reported confidence. Not a verification of the source.
    pub confidence: Option<f32>,
}

impl AiSummaryInput {
    /// SHA-256 of the summary text alone.
    pub fn content_hash(&self) -> Sha256Hash {
        sha256_bytes(self.summary.as_bytes())
    }
}

/// Everything the operator asked to export.
///
/// `ai_summaries` stay separate from `sources`. A summary whose `source_path`
/// is not one of `sources` is rejected before any file is read or written.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VaultInput {
    pub sources: Vec<SourceInput>,
    pub ai_summaries: Vec<AiSummaryInput>,
}

/// Result of a successful [`export_vault`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportReceipt {
    /// Export format version. Currently 1. Serialized first in the export file.
    pub version: u32,
    /// SHA-256 of the canonical JSON encoding of the [`VaultInput`].
    pub vault_fingerprint: Sha256Hash,
    pub source_count: u64,
    pub summary_count: u64,
    /// Custody chain head hash (`ChainHead::top_hash`) after the sources were appended.
    pub custody_top_hash: Sha256Hash,
    /// Wall-clock seconds since the Unix epoch at export.
    pub exported_at_unix: u64,
}

/// One row of the timeline index.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub seq: u64,
    pub timestamp_unix: u64,
    pub digest: FileDigest,
    pub label: RecordLabel,
    /// Operator-supplied description. Stays claimed across [`Manifest::recheck`].
    pub claimed: ClaimedMetadata,
}

/// Vault index ordered by custody time, then sequence.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
}

fn manifest_from_entries(mut entries: Vec<CustodyEntry>) -> Manifest {
    entries.sort_by(|left, right| {
        left.timestamp_unix
            .cmp(&right.timestamp_unix)
            .then(left.seq.cmp(&right.seq))
    });
    let entries = entries
        .into_iter()
        .map(|entry| ManifestEntry {
            seq: entry.seq,
            timestamp_unix: entry.timestamp_unix,
            digest: FileDigest {
                path: PathBuf::from(entry.path),
                hash: entry.hash,
            },
            label: RecordLabel::Claimed,
            claimed: ClaimedMetadata::default(),
        })
        .collect();
    Manifest { entries }
}

impl Manifest {
    /// Build a timeline index from `log`.
    ///
    /// The chain is checked so a broken log is not indexed. Every entry is
    /// labeled [`RecordLabel::Claimed`] because this does not re-hash the files.
    pub fn from_custody_log(log: &CustodyLog) -> Result<Self> {
        log.verify_chain()?;
        let entries = log.entries_from(0)?;
        Ok(manifest_from_entries(entries))
    }

    /// Re-check each content hash against the custody chain and the file bytes.
    ///
    /// On success every entry label becomes [`RecordLabel::Verified`].
    /// [`ManifestEntry::claimed`] is left untouched. On failure labels stay
    /// [`RecordLabel::Claimed`].
    pub fn recheck(&mut self, log: &CustodyLog) -> Result<()> {
        log.verify_chain()?;
        let trusted: Vec<(PathBuf, Sha256Hash)> = self
            .entries
            .iter()
            .map(|entry| (entry.digest.path.clone(), entry.digest.hash))
            .collect();
        verify_before_trust(&trusted)?;
        for entry in &mut self.entries {
            entry.label = RecordLabel::Verified;
        }
        Ok(())
    }
}

fn sha256_bytes(bytes: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Sha256Hash::from_bytes(hasher.finalize().into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Compact JSON of `input` in struct field order.
///
/// This byte string is what [`ExportReceipt::vault_fingerprint`] hashes. It
/// does not include source-file bytes, custody timestamps, or the on-disk index.
fn canonical_vault_json(input: &VaultInput) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(input)?)
}

fn fingerprint_vault(input: &VaultInput) -> Result<Sha256Hash> {
    Ok(sha256_bytes(&canonical_vault_json(input)?))
}

/// Reject summaries that do not name a source in `input`. Performs no IO.
fn validate_summary_refs(input: &VaultInput) -> Result<()> {
    let known: HashSet<&Path> = input
        .sources
        .iter()
        .map(|source| source.path.as_path())
        .collect();
    for summary in &input.ai_summaries {
        if !known.contains(summary.source_path.as_path()) {
            return Err(Error::Invalid(format!(
                "AI summary references unknown source: {}",
                summary.source_path.display()
            )));
        }
    }
    Ok(())
}

fn hash_sources(input: &VaultInput) -> Result<Vec<FileDigest>> {
    input
        .sources
        .iter()
        .map(|source| hash_file(&source.path))
        .collect()
}

fn utf8_path(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        Error::Invalid(format!(
            "source path is not valid UTF-8: {}",
            path.display()
        ))
    })
}

fn source_for<'a>(input: &'a VaultInput, path: &Path) -> Result<&'a SourceInput> {
    input
        .sources
        .iter()
        .find(|source| source.path == path)
        .ok_or_else(|| Error::NotIngested(path.display().to_string()))
}

/// Read `version` as the first field of an export object.
fn leading_version(bytes: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(bytes)
        .map_err(|err| Error::Invalid(format!("export is not utf-8: {err}")))?;
    let Some(rest) = text.trim_start().strip_prefix('{') else {
        return Err(Error::Invalid("export is not a JSON object".into()));
    };
    let rest = rest.trim_start();
    let Some(after_key) = rest.strip_prefix("\"version\"") else {
        return Err(Error::Invalid(
            "export version must be the first field".into(),
        ));
    };
    let Some(after_colon) = after_key.trim_start().strip_prefix(':') else {
        return Err(Error::Invalid(
            "export version must be the first field".into(),
        ));
    };
    let digits = after_colon.trim_start();
    let end = digits
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(digits.len());
    if end == 0 {
        return Err(Error::Invalid("export version is missing".into()));
    }
    digits[..end]
        .parse()
        .map_err(|err| Error::Invalid(format!("bad export version: {err}")))
}

#[derive(Serialize)]
struct IndexedSource {
    path: PathBuf,
    category: Category,
    /// `verified` only after the content hash was re-checked.
    label: RecordLabel,
    claimed: ClaimedMetadata,
    content_hash: Sha256Hash,
    custody_seq: u64,
    custody_time_unix: u64,
}

#[derive(Serialize)]
struct IndexedSummary {
    source_path: PathBuf,
    model: String,
    summary: String,
    confidence: Option<f32>,
    /// SHA-256 of the summary text. Separate from the source content hash.
    summary_hash: Sha256Hash,
    /// Summaries are not file re-checks, so this stays claimed.
    label: RecordLabel,
}

/// On-disk export. `version` is the first field on purpose.
#[derive(Serialize)]
struct VaultIndex {
    version: u32,
    vault_fingerprint: Sha256Hash,
    source_count: u64,
    summary_count: u64,
    custody_top_hash: Sha256Hash,
    exported_at_unix: u64,
    /// Sources in custody-time order, then sequence order.
    sources: Vec<IndexedSource>,
    /// AI summaries kept separate from sources. Each carries its own hash.
    ai_summaries: Vec<IndexedSummary>,
}

fn write_index(
    vault_path: &Path,
    input: &VaultInput,
    manifest: &Manifest,
    fingerprint: Sha256Hash,
    custody_top_hash: Sha256Hash,
    exported_at_unix: u64,
) -> Result<()> {
    let mut sources = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let source = source_for(input, &entry.digest.path)?;
        sources.push(IndexedSource {
            path: entry.digest.path.clone(),
            category: source.category,
            label: entry.label,
            claimed: entry.claimed.clone(),
            content_hash: entry.digest.hash,
            custody_seq: entry.seq,
            custody_time_unix: entry.timestamp_unix,
        });
    }
    let ai_summaries = input
        .ai_summaries
        .iter()
        .map(|summary| IndexedSummary {
            source_path: summary.source_path.clone(),
            model: summary.model.clone(),
            summary: summary.summary.clone(),
            confidence: summary.confidence,
            summary_hash: summary.content_hash(),
            label: RecordLabel::Claimed,
        })
        .collect();
    let index = VaultIndex {
        version: VAULT_VERSION,
        vault_fingerprint: fingerprint,
        source_count: input.sources.len() as u64,
        summary_count: input.ai_summaries.len() as u64,
        custody_top_hash,
        exported_at_unix,
        sources,
        ai_summaries,
    };
    let mut json = serde_json::to_vec_pretty(&index)?;
    json.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(vault_path)?;
    file.write_all(&json)?;
    file.sync_all()?;
    Ok(())
}

/// Hash every source, append them to the custody log, and write the vault index.
///
/// AI summary references are checked before any file is opened. A summary that
/// names a path outside `input.sources` returns [`Error::Invalid`] and leaves
/// the filesystem untouched. The written index is ordered by custody time and
/// then sequence. Its first JSON field is `version`. The receipt's
/// `custody_top_hash` is the custody chain head hash.
///
/// File-hash labels in the index are [`RecordLabel::Verified`] only because
/// [`Manifest::recheck`] passed. Summary labels and claimed metadata stay claimed.
pub fn export_vault<P: AsRef<Path>>(vault_path: P, input: &VaultInput) -> Result<ExportReceipt> {
    validate_summary_refs(input)?;

    let vault_path = vault_path.as_ref();
    let fingerprint = fingerprint_vault(input)?;
    let digests = hash_sources(input)?;

    let custody_path = vault_path.with_extension("custody");
    let mut log = CustodyLog::open(&custody_path)?;
    for digest in &digests {
        let path = utf8_path(&digest.path)?;
        log.append(path, digest.hash)?;
    }
    let head = log.verify_chain()?;
    let mut manifest = Manifest::from_custody_log(&log)?;
    for entry in &mut manifest.entries {
        entry.claimed = source_for(input, &entry.digest.path)?.claimed.clone();
    }
    manifest.recheck(&log)?;
    let exported_at_unix = unix_now();
    write_index(
        vault_path,
        input,
        &manifest,
        fingerprint,
        head.top_hash,
        exported_at_unix,
    )?;

    Ok(ExportReceipt {
        version: VAULT_VERSION,
        vault_fingerprint: fingerprint,
        source_count: input.sources.len() as u64,
        summary_count: input.ai_summaries.len() as u64,
        custody_top_hash: head.top_hash,
        exported_at_unix,
    })
}

fn verify_export_v1(vault_path: &Path) -> Result<Vec<FileDigest>> {
    let custody_path = vault_path.with_extension("custody");
    if !custody_path.is_file() {
        return Err(Error::NotIngested(custody_path.display().to_string()));
    }
    let log = CustodyLog::open(&custody_path)?;
    let mut manifest = Manifest::from_custody_log(&log)?;
    manifest.recheck(&log)?;
    Ok(manifest
        .entries
        .into_iter()
        .map(|entry| entry.digest)
        .collect())
}

/// Read the export `version` first, then re-check that format.
///
/// Version 1 re-checks the custody chain and then the file bytes. Any other
/// version is [`Error::Invalid`]. The version field has to be the first JSON
/// field; otherwise the export is rejected before the chain is opened.
pub fn verify_vault<P: AsRef<Path>>(vault_path: P) -> Result<Vec<FileDigest>> {
    let vault_path = vault_path.as_ref();
    let bytes = std::fs::read(vault_path)?;
    match leading_version(&bytes)? {
        1 => verify_export_v1(vault_path),
        version => Err(Error::Invalid(format!("unknown export version {version}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn temp_file(data: impl AsRef<[u8]>) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(data.as_ref()).unwrap();
        file.flush().unwrap();
        file
    }

    fn source(path: PathBuf, ext: &str, claimed: ClaimedMetadata) -> SourceInput {
        SourceInput {
            path,
            category: Category::from_extension(ext),
            claimed,
        }
    }

    fn custody_entry(seq: u64, timestamp_unix: u64, path: &str, byte: u8) -> CustodyEntry {
        CustodyEntry {
            seq,
            path: path.to_string(),
            hash: Sha256Hash::from_bytes([byte; 32]),
            prev_hash: Sha256Hash::from_bytes([0u8; 32]),
            timestamp_unix,
        }
    }

    #[test]
    fn category_from_extension() {
        assert_eq!(Category::from_extension("pdf"), Category::Document);
        assert_eq!(Category::from_extension("DOCX"), Category::Document);
        assert_eq!(Category::from_extension(".txt"), Category::Document);
        assert_eq!(Category::from_extension("png"), Category::Image);
        assert_eq!(Category::from_extension("JPEG"), Category::Image);
        assert_eq!(Category::from_extension(".svg"), Category::Image);
        assert_eq!(Category::from_extension("mp4"), Category::Video);
        assert_eq!(Category::from_extension("WEBM"), Category::Video);
        assert_eq!(Category::from_extension("mp3"), Category::Audio);
        assert_eq!(Category::from_extension("flac"), Category::Audio);
        assert_eq!(Category::from_extension("exe"), Category::Binary);
        assert_eq!(Category::from_extension("bin"), Category::Binary);
        assert_eq!(Category::from_extension("zip"), Category::Other);
        assert_eq!(Category::from_extension(""), Category::Other);
        assert_eq!(Category::from_extension("..."), Category::Other);
    }

    #[test]
    fn manifest_built_from_custody_log() {
        let scrambled = manifest_from_entries(vec![
            custody_entry(1, 50, "late.txt", 1),
            custody_entry(5, 10, "second.txt", 5),
            custody_entry(4, 10, "first.txt", 4),
        ]);
        let order: Vec<_> = scrambled
            .entries
            .iter()
            .map(|entry| (entry.timestamp_unix, entry.seq, entry.digest.path.clone()))
            .collect();
        assert_eq!(
            order,
            vec![
                (10, 4, PathBuf::from("first.txt")),
                (10, 5, PathBuf::from("second.txt")),
                (50, 1, PathBuf::from("late.txt")),
            ]
        );
        assert!(scrambled
            .entries
            .iter()
            .all(|entry| entry.label == RecordLabel::Claimed));
        assert_eq!(
            scrambled.entries[0].digest.hash,
            Sha256Hash::from_bytes([4u8; 32])
        );

        let log_file = NamedTempFile::new().unwrap();
        let mut log = CustodyLog::open(log_file.path()).unwrap();
        let first = temp_file(b"one");
        let second = temp_file(b"two");
        let digest_first = hash_file(first.path()).unwrap();
        let digest_second = hash_file(second.path()).unwrap();
        log.append(first.path().to_str().unwrap(), digest_first.hash)
            .unwrap();
        log.append(second.path().to_str().unwrap(), digest_second.hash)
            .unwrap();

        let manifest = Manifest::from_custody_log(&log).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        for pair in manifest.entries.windows(2) {
            let left = (pair[0].timestamp_unix, pair[0].seq);
            let right = (pair[1].timestamp_unix, pair[1].seq);
            assert!(
                left < right,
                "expected custody time then seq, {left:?} then {right:?}"
            );
        }
        assert_eq!(manifest.entries[0].seq, 0);
        assert_eq!(manifest.entries[1].seq, 1);
        assert_eq!(manifest.entries[0].digest.path, first.path());
        assert_eq!(manifest.entries[0].digest.hash, digest_first.hash);
        assert_eq!(manifest.entries[1].digest.path, second.path());
        assert_eq!(manifest.entries[1].digest.hash, digest_second.hash);
        assert_eq!(manifest.entries[0].label, RecordLabel::Claimed);
        assert_eq!(log.head().top_hash, log.verify_chain().unwrap().top_hash);
    }

    #[test]
    fn label_accuracy_claimed_versus_verified() {
        let log_file = NamedTempFile::new().unwrap();
        let mut log = CustodyLog::open(log_file.path()).unwrap();
        let source = temp_file(b"original-bytes");
        let digest = hash_file(source.path()).unwrap();
        log.append(source.path().to_str().unwrap(), digest.hash)
            .unwrap();

        let mut manifest = Manifest::from_custody_log(&log).unwrap();
        assert_eq!(manifest.entries[0].label, RecordLabel::Claimed);
        assert_eq!(
            serde_json::to_value(manifest.entries[0].label).unwrap(),
            serde_json::json!("claimed")
        );
        manifest.entries[0].claimed.title = Some("Operator title".into());
        let claimed_before = serde_json::to_value(&manifest.entries[0].claimed).unwrap();
        assert_eq!(claimed_before["title"]["label"], CLAIM_LABEL);
        assert!(claimed_before["title"].get("verified").is_none());

        std::fs::write(source.path(), b"tampered").unwrap();
        let err = manifest.recheck(&log).unwrap_err();
        match err {
            Error::Mismatch(list) => assert_eq!(list.len(), 1),
            other => panic!("expected Mismatch, got {other}"),
        }
        assert_eq!(manifest.entries[0].label, RecordLabel::Claimed);
        assert_eq!(
            manifest.entries[0].claimed.title.as_deref(),
            Some("Operator title")
        );

        std::fs::write(source.path(), b"original-bytes").unwrap();
        manifest.recheck(&log).unwrap();
        assert_eq!(manifest.entries[0].label, RecordLabel::Verified);
        assert_eq!(
            serde_json::to_value(manifest.entries[0].label).unwrap(),
            serde_json::json!("verified")
        );
        let claimed_after = serde_json::to_value(&manifest.entries[0].claimed).unwrap();
        assert_eq!(claimed_before, claimed_after);
        assert_eq!(manifest.entries[0].digest.hash, digest.hash);
    }

    #[test]
    fn export_and_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let src_a = dir.path().join("exhibit.pdf");
        let src_b = dir.path().join("photo.png");
        std::fs::write(&src_a, b"pdf-bytes").unwrap();
        std::fs::write(&src_b, b"png-bytes").unwrap();
        let input = VaultInput {
            sources: vec![
                source(
                    src_a.clone(),
                    "pdf",
                    ClaimedMetadata {
                        title: Some("Exhibit A".into()),
                        ..ClaimedMetadata::default()
                    },
                ),
                source(src_b.clone(), "png", ClaimedMetadata::default()),
            ],
            ai_summaries: vec![AiSummaryInput {
                source_path: src_a.clone(),
                model: "local-test".into(),
                summary: "A short summary of the pdf.".into(),
                confidence: Some(0.25),
            }],
        };
        let vault = dir.path().join("evidence.json");
        let receipt = export_vault(&vault, &input).unwrap();

        assert_eq!(receipt.version, 1);
        assert_eq!(receipt.source_count, 2);
        assert_eq!(receipt.summary_count, 1);
        assert!(receipt.exported_at_unix > 1_700_000_000);
        assert_ne!(receipt.custody_top_hash, Sha256Hash::from_bytes([0u8; 32]));
        let canonical = serde_json::to_vec(&input).unwrap();
        assert_eq!(receipt.vault_fingerprint, sha256_bytes(&canonical));
        assert!(vault.with_extension("custody").is_file());

        let raw = std::fs::read_to_string(&vault).unwrap();
        assert_version_is_first_field(&raw);
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc["version"].as_u64().unwrap(), 1);
        assert_eq!(doc["source_count"].as_u64().unwrap(), 2);
        assert_eq!(doc["summary_count"].as_u64().unwrap(), 1);
        assert_eq!(
            doc["vault_fingerprint"].as_str().unwrap(),
            receipt.vault_fingerprint.to_hex()
        );
        assert_eq!(
            doc["custody_top_hash"].as_str().unwrap(),
            receipt.custody_top_hash.to_hex()
        );
        assert_eq!(
            doc["exported_at_unix"].as_u64().unwrap(),
            receipt.exported_at_unix
        );
        assert_eq!(doc["sources"][0]["category"].as_str().unwrap(), "Document");
        assert_eq!(doc["sources"][0]["label"].as_str().unwrap(), "verified");
        assert_eq!(doc["sources"][1]["label"].as_str().unwrap(), "verified");
        assert_eq!(
            doc["sources"][0]["claimed"]["title"]["label"]
                .as_str()
                .unwrap(),
            CLAIM_LABEL
        );
        let summary_hash = input.ai_summaries[0].content_hash();
        assert_eq!(
            doc["ai_summaries"][0]["summary_hash"].as_str().unwrap(),
            summary_hash.to_hex()
        );
        assert_eq!(doc["ai_summaries"][0]["label"].as_str().unwrap(), "claimed");
        assert_ne!(
            doc["ai_summaries"][0]["summary_hash"].as_str().unwrap(),
            doc["sources"][0]["content_hash"].as_str().unwrap()
        );
        for indexed in doc["sources"].as_array().unwrap() {
            assert!(indexed.get("summary").is_none());
            assert!(indexed.get("summary_hash").is_none());
            assert!(indexed.get("content_hash").is_some());
        }
        assert_eq!(doc["ai_summaries"].as_array().unwrap().len(), 1);
        assert_eq!(
            doc["ai_summaries"][0]["source_path"].as_str().unwrap(),
            src_a.to_str().unwrap()
        );
        let times: Vec<_> = doc["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["custody_time_unix"].as_u64().unwrap(),
                    entry["custody_seq"].as_u64().unwrap(),
                )
            })
            .collect();
        assert!(times.windows(2).all(|pair| pair[0] <= pair[1]));

        let verified = verify_vault(&vault).unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].hash, hash_file(&src_a).unwrap().hash);
        assert_eq!(verified[1].hash, hash_file(&src_b).unwrap().hash);
        assert_eq!(verified[0].path, src_a);

        // The chain is checked before file bytes. A truncated log is
        // `ChainBroken` even when a source was also rewritten.
        std::fs::write(&src_a, b"tampered-bytes").unwrap();
        let custody = vault.with_extension("custody");
        let mut custody_raw = std::fs::read(&custody).unwrap();
        assert!(custody_raw.len() > 8);
        custody_raw.truncate(custody_raw.len() / 2);
        std::fs::write(&custody, custody_raw).unwrap();
        let err = verify_vault(&vault).unwrap_err();
        assert!(matches!(err, Error::ChainBroken { .. }), "{err}");
    }

    #[test]
    fn export_version_is_first_field() {
        let dir = tempfile::tempdir().unwrap();
        let file = temp_file(b"versioned-bytes");
        let vault = dir.path().join("vault.json");
        let input = VaultInput {
            sources: vec![source(
                file.path().to_path_buf(),
                "txt",
                ClaimedMetadata::default(),
            )],
            ai_summaries: Vec::new(),
        };
        let receipt = export_vault(&vault, &input).unwrap();
        assert_eq!(receipt.version, 1);
        assert_ne!(receipt.custody_top_hash, Sha256Hash::from_bytes([0u8; 32]));

        let raw = std::fs::read_to_string(&vault).unwrap();
        assert_version_is_first_field(&raw);
        assert_eq!(leading_version(raw.as_bytes()).unwrap(), 1);

        std::fs::write(file.path(), b"changed-after-export").unwrap();
        let unknown = raw.replacen("\"version\": 1", "\"version\": 99", 1);
        assert_ne!(unknown, raw);
        assert_version_is_first_field(&unknown);
        std::fs::write(&vault, &unknown).unwrap();
        let err = verify_vault(&vault).unwrap_err();
        match err {
            Error::Invalid(message) => {
                assert!(message.contains("unknown export version 99"), "{message}")
            }
            other => panic!("expected Invalid, got {other}"),
        }

        let displaced = raw.replacen('{', "{\n  \"note\": \"not-the-version\",", 1);
        std::fs::write(&vault, displaced).unwrap();
        let err = verify_vault(&vault).unwrap_err();
        match err {
            Error::Invalid(message) => {
                assert!(message.contains("first field"), "{message}");
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    fn assert_version_is_first_field(raw: &str) {
        let rest = raw.trim_start().strip_prefix('{').expect("JSON object");
        let rest = rest.trim_start();
        assert!(
            rest.starts_with("\"version\""),
            "version must be the first field, got {rest}"
        );
    }

    #[test]
    fn export_rejects_orphan_summary() {
        let dir = tempfile::tempdir().unwrap();
        let listed = dir.path().join("listed.txt");
        let orphan = dir.path().join("not-listed.txt");
        let vault = dir.path().join("vault.json");
        let input = VaultInput {
            sources: vec![source(listed, "txt", ClaimedMetadata::default())],
            ai_summaries: vec![AiSummaryInput {
                source_path: orphan,
                model: "local-test".into(),
                summary: "This source was never offered.".into(),
                confidence: None,
            }],
        };

        let err = export_vault(&vault, &input).unwrap_err();
        match err {
            Error::Invalid(message) => {
                assert!(message.contains("unknown source"), "{message}");
                assert!(message.contains("not-listed.txt"), "{message}");
            }
            other => panic!("expected Error::Invalid, got {other}"),
        }
        assert!(!vault.exists());
        assert!(!vault.with_extension("custody").exists());
    }

    #[test]
    fn claimed_metadata_never_auto_verified() {
        let meta = ClaimedMetadata {
            title: Some("Specimen".into()),
            description: Some("Unreviewed scan".into()),
            author: Some("operator".into()),
            created_date: Some("2024-01-02".into()),
            tags: vec!["draft".into(), "lab".into()],
            notes: Some("not checked".into()),
        };
        assert_labeled(&serde_json::to_value(&meta).unwrap());
        assert_labeled(&serde_json::to_value(ClaimedMetadata::default()).unwrap());
    }

    fn assert_labeled(value: &serde_json::Value) {
        let obj = value
            .as_object()
            .expect("claimed metadata is a JSON object");
        let fields = [
            "title",
            "description",
            "author",
            "created_date",
            "tags",
            "notes",
        ];
        assert_eq!(obj.len(), fields.len());
        for field in fields {
            let labeled = obj
                .get(field)
                .unwrap_or_else(|| panic!("missing {field}"))
                .as_object()
                .unwrap_or_else(|| panic!("{field} is not an object"));
            assert_eq!(labeled.len(), 2, "{field} should only have label and value");
            assert_eq!(
                labeled.get("label").and_then(|label| label.as_str()),
                Some(CLAIM_LABEL),
                "{field}"
            );
            assert!(!labeled.contains_key("verified"));
        }
        assert!(!value.to_string().contains("\"verified\""));
        assert_no_bool(value);
    }

    fn assert_no_bool(value: &serde_json::Value) {
        match value {
            serde_json::Value::Bool(_) => panic!("bool field in claimed metadata: {value}"),
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_bool(item);
                }
            }
            serde_json::Value::Object(map) => {
                assert!(!map.contains_key("verified"));
                for child in map.values() {
                    assert_no_bool(child);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn vault_fingerprint_stable() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("note.txt");
        std::fs::write(&source_path, b"same-bytes").unwrap();
        let input = VaultInput {
            sources: vec![source(
                source_path.clone(),
                "txt",
                ClaimedMetadata {
                    title: Some("Stable".into()),
                    tags: vec!["one".into()],
                    ..ClaimedMetadata::default()
                },
            )],
            ai_summaries: vec![AiSummaryInput {
                source_path: source_path.clone(),
                model: "local-test".into(),
                summary: "Unchanged summary.".into(),
                confidence: None,
            }],
        };

        let first = export_vault(dir.path().join("one.json"), &input).unwrap();
        let second = export_vault(dir.path().join("two.json"), &input).unwrap();
        let canonical = serde_json::to_vec(&input).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let expected = Sha256Hash::from_bytes(hasher.finalize().into());
        assert_eq!(first.vault_fingerprint, second.vault_fingerprint);
        assert_eq!(first.vault_fingerprint, expected);
        assert_eq!(first.version, 1);
        assert_ne!(first.custody_top_hash, Sha256Hash::from_bytes([0u8; 32]));

        let mut changed = input.clone();
        changed.sources[0].claimed.title = Some("Rewritten claim".into());
        let changed_receipt = export_vault(dir.path().join("changed.json"), &changed).unwrap();
        assert_ne!(changed_receipt.vault_fingerprint, first.vault_fingerprint);

        std::fs::write(&source_path, b"completely different bytes").unwrap();
        let reread = export_vault(dir.path().join("reread.json"), &input).unwrap();
        assert_eq!(reread.vault_fingerprint, first.vault_fingerprint);
        assert_ne!(reread.custody_top_hash, first.custody_top_hash);
    }
}
