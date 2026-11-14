//! Timeline-ordered evidence vault index.
//!
//! Local-only: this module makes no network calls and uses no credentials.
//! Source files are hashed and appended to a custody log. AI summaries stay in
//! their own section and carry their own content hashes. Metadata on a source
//! is claimed and never verified.

use crate::custody::CustodyLog;
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
/// There is no verified state. This label is the whole status of the value.
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
/// Every field is claimed and never verified. The vault stores the assertion
/// the operator made. It does not record a verification result, and this
/// struct has no `verified` flag.
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
/// and is never treated as the source file hash.
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
    /// Export format version. Currently 1.
    pub version: u32,
    /// SHA-256 of the canonical JSON encoding of the [`VaultInput`].
    pub vault_fingerprint: Sha256Hash,
    pub source_count: u64,
    pub summary_count: u64,
    /// Top hash of the custody log after every source was appended.
    pub custody_top_hash: Sha256Hash,
    /// Wall-clock seconds since the Unix epoch at export.
    pub exported_at_unix: u64,
}

#[derive(Serialize)]
struct IndexedSource {
    path: PathBuf,
    category: Category,
    claimed: ClaimedMetadata,
    content_hash: Sha256Hash,
    custody_seq: u64,
}

#[derive(Serialize)]
struct IndexedSummary {
    source_path: PathBuf,
    model: String,
    summary: String,
    confidence: Option<f32>,
    /// SHA-256 of the summary text. Separate from the source content hash.
    summary_hash: Sha256Hash,
}

#[derive(Serialize)]
struct VaultIndex {
    version: u32,
    vault_fingerprint: Sha256Hash,
    source_count: u64,
    summary_count: u64,
    custody_top_hash: Sha256Hash,
    exported_at_unix: u64,
    /// Sources in custody (timeline) order.
    sources: Vec<IndexedSource>,
    /// AI summaries kept separate from sources. Each carries its own hash.
    ai_summaries: Vec<IndexedSummary>,
}

fn sha256_bytes(bytes: &[u8]) -> Sha256Hash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Sha256Hash::from_bytes(hasher.finalize().into())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compact JSON of `input` in struct field order.
///
/// This byte string is the canonical encoding behind
/// [`ExportReceipt::vault_fingerprint`]. It does not include source-file
/// bytes, custody timestamps, or the on-disk index.
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

fn write_index(
    vault_path: &Path,
    input: &VaultInput,
    digests: &[FileDigest],
    seqs: &[u64],
    fingerprint: Sha256Hash,
    custody_top_hash: Sha256Hash,
    exported_at_unix: u64,
) -> Result<()> {
    let sources = input
        .sources
        .iter()
        .enumerate()
        .map(|(i, source)| IndexedSource {
            path: source.path.clone(),
            category: source.category,
            claimed: source.claimed.clone(),
            content_hash: digests[i].hash,
            custody_seq: seqs[i],
        })
        .collect();
    let ai_summaries = input
        .ai_summaries
        .iter()
        .map(|summary| IndexedSummary {
            source_path: summary.source_path.clone(),
            model: summary.model.clone(),
            summary: summary.summary.clone(),
            confidence: summary.confidence,
            summary_hash: summary.content_hash(),
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
/// the filesystem untouched. Summaries are written in their own section of the
/// index and are not custody entries; each one carries [`AiSummaryInput::content_hash`].
///
/// The custody file is `vault_path` with its extension replaced by `custody`.
/// Sources are appended in input order, which is the vault timeline.
pub fn export_vault<P: AsRef<Path>>(vault_path: P, input: &VaultInput) -> Result<ExportReceipt> {
    validate_summary_refs(input)?;

    let vault_path = vault_path.as_ref();
    let fingerprint = fingerprint_vault(input)?;
    let digests = hash_sources(input)?;

    let custody_path = vault_path.with_extension("custody");
    let mut log = CustodyLog::open(&custody_path)?;
    let mut seqs = Vec::with_capacity(digests.len());
    for digest in &digests {
        let path = utf8_path(&digest.path)?;
        seqs.push(log.append(path, digest.hash)?);
    }
    let head = log.verify_chain()?;
    let exported_at_unix = unix_now();
    write_index(
        vault_path,
        input,
        &digests,
        &seqs,
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

/// Re-check the custody log beside `vault_path`, then re-hash every logged file.
///
/// The custody file is `vault_path` with its extension replaced by `custody`.
/// [`CustodyLog::verify_chain`] runs first. Only a chain that still links is
/// handed to [`verify_before_trust`]. A missing custody file is
/// [`Error::NotIngested`] and is not created.
pub fn verify_vault<P: AsRef<Path>>(vault_path: P) -> Result<Vec<FileDigest>> {
    let custody_path = vault_path.as_ref().with_extension("custody");
    if !custody_path.is_file() {
        return Err(Error::NotIngested(custody_path.display().to_string()));
    }
    let log = CustodyLog::open(&custody_path)?;
    log.verify_chain()?;
    let entries = log.entries_from(0)?;
    let trusted: Vec<(PathBuf, Sha256Hash)> = entries
        .iter()
        .map(|entry| (PathBuf::from(&entry.path), entry.hash))
        .collect();
    verify_before_trust(&trusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn source(path: PathBuf, ext: &str, claimed: ClaimedMetadata) -> SourceInput {
        SourceInput {
            path,
            category: Category::from_extension(ext),
            claimed,
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

        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&vault).unwrap()).unwrap();
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

        let verified = verify_vault(&vault).unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].hash, hash_file(&src_a).unwrap().hash);
        assert_eq!(verified[1].hash, hash_file(&src_b).unwrap().hash);
        assert_eq!(verified[0].path, src_a);

        // The chain is checked before file bytes. A truncated log is
        // `ChainBroken` even when a source was also rewritten.
        std::fs::write(&src_a, b"tampered-bytes").unwrap();
        let custody = vault.with_extension("custody");
        let mut raw = std::fs::read(&custody).unwrap();
        assert!(raw.len() > 8);
        raw.truncate(raw.len() / 2);
        std::fs::write(&custody, raw).unwrap();
        let err = verify_vault(&vault).unwrap_err();
        assert!(matches!(err, Error::ChainBroken { .. }), "{err}");
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
                labeled.get("label").and_then(|v| v.as_str()),
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
