---
name: ip-sentinel
description: >
  Builds a tamper-evident cryptographic custody vault over files stored on a
  UGREEN AI NAS. Inventories a target folder, computes SHA-256 fingerprints via
  ug-filesystem sha256sum, cross-checks photo and document content with
  ug-photo vision-ocr and ug-document extract, chains every fingerprint into an
  append-only hash-linked custody log, labels each entry claimed versus verified,
  and exports a versioned custody receipt — only after explicit user confirmation.
  Use when the user asks to fingerprint, seal, verify, audit, or export evidence
  for files on the NAS. Do NOT use for general file organization, photo albums,
  or document summarization without a custody or verification goal.
---

# IP Sentinel

## User goal

Seal a folder of files on the NAS into a court-of-record style custody vault:
every file gets a SHA-256 fingerprint, every fingerprint joins a hash-chained
log, and any later tampering is detectable before anything is exported.

## Required inputs

- Target folder path on the NAS (required).
- Optional scope label (e.g., incident name, case ID) for the custody receipt.
- Optional list of file extensions to include; default is all supported types.

## Supported CLI capabilities

| Step | CLI | Action | Mode |
|------|-----|--------|------|
| 1 | ug-filesystem | find | read-only |
| 2 | ug-filesystem | stat | read-only |
| 3 | ug-filesystem | sha256sum | read-only |
| 4 | ug-photo | vision-ocr | read-only |
| 5 | ug-document | extract | read-only |
| 6 | ug-knowledge | save-text | write, confirmation-gated |
| 7 | ug-filesystem | mkdir | write, confirmation-gated |

## Orchestration workflow

Delegate each step to the registered expert. Pass only the real output of the
previous step forward. Never reference a prior result by vague description.

1. **Inventory** — delegate to file-agent: `ug-filesystem find` on the target
   folder with the optional extension filter. If the result is empty, say so
   clearly and stop. Do not substitute similar folders.
2. **Metadata** — delegate to file-agent: `ug-filesystem stat` on each path
   from step 1. Record size, mtime, and type per file.
3. **Fingerprint** — delegate to file-agent: `ug-filesystem sha256sum` on each
   path. This is the cryptographic core: every digest is computed locally on
   the NAS, never uploaded.
4. **Content cross-check** — for image files, delegate to photo-agent:
   `ug-photo vision-ocr` to confirm readable content matches expectations. For
   documents, delegate to document-agent: `ug-document extract`. Mismatches
   between claimed type and extracted content are flagged, not silently fixed.
5. **Chain** — assemble the append-only hash-chained custody log: each entry
   carries its own SHA-256 digest, the previous entry's chain hash, a
   monotonic sequence number, and a UTC timestamp. The chain head is the
   hash of the last entry. Truncation or reordering breaks the chain and is
   reported as a chain-break, not repaired.
6. **Label** — each entry is labeled `verified` only when its digest was
   re-checked against both the live file and the chain. Operator-supplied
   metadata (scope label, notes) stays labeled `claimed` forever.
7. **Export proposal** — build the versioned custody receipt (see
   references/custody-receipt-format.md). The export JSON begins with
   `"version": 1`. `verify_vault` rejects any other version or any file whose
   first field is not `version`.
8. **Confirm** — present the receipt summary and the list of files to be
   written. Wait for explicit user confirmation before any write.
9. **Write** — after confirmation, delegate to knowledge-agent:
   `ug-knowledge save-text` for the receipt, and file-agent: `ug-filesystem
   mkdir` for the output folder if needed. Original files are never moved,
   renamed, overwritten, or deleted.

## Delegation state handling

Handle all five states on every delegation:

- **completed** — use the returned result as the input to the next step.
- **failed** — report the failure, keep any partial results already collected,
  label them `partial`, and ask whether to continue with the remainder or abort.
- **cancelled** — stop the workflow, report what was completed, do not retry.
- **waiting_user** — surface the prompt to the user verbatim and pause.
- **waiting_approval** — surface the approval request and pause until granted
  or denied.

## Completion

The skill completes when the custody receipt is saved and the chain head hash
is reported to the user, or when the workflow aborts with a clear reason.

## Failure

- No files found: state it, stop, suggest checking the path.
- A file disappears between stat and sha256sum: flag it as `missing-at-fingerprint`,
  do not hash a substitute.
- Chain break on re-verify: report the sequence number where it broke and the
  expected versus actual hash. Never auto-repair.
- Unsupported file type: list it under `unsupported` in the receipt rather than
  skipping silently.
- Any write without confirmation: refuse.

## References

- [Capability map](references/capability-map.md)
- [Custody receipt format](references/custody-receipt-format.md)
- [Validation plan](references/validation-plan.md)
- [Third-party disclosure](references/third-party-disclosure.md)
