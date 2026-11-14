# Custody Receipt Format

Version 1. The export JSON MUST begin with the field `"version": 1` as its
first key. `verify_vault` rejects any receipt whose first field is not
`version`, or whose version is anything other than 1.

## Top-level fields

```json
{
  "version": 1,
  "scope_label": "<operator-supplied, claimed>",
  "created_utc": "<ISO-8601>",
  "chain_head": "<SHA-256 of final custody entry>",
  "file_count": 0,
  "verified_count": 0,
  "claimed_count": 0,
  "unsupported": [],
  "missing_at_fingerprint": [],
  "chain_breaks": [],
  "entries": []
}
```

## Entry fields

```json
{
  "sequence": 0,
  "path": "<relative path>",
  "sha256": "<hex digest>",
  "prev_chain_hash": "<hex, null for sequence 0>",
  "chain_hash": "<hex>",
  "size_bytes": 0,
  "mtime_utc": "<ISO-8601>",
  "label": "verified | claimed | partial | unsupported | missing-at-fingerprint",
  "cross_check": "ocr-pass | ocr-mismatch | extract-pass | extract-mismatch | skipped"
}
```

## Label semantics

- **verified** — digest re-checked against the live file AND consistent with the
  chain. Strongest claim the receipt can make.
- **claimed** — operator metadata or entries the engine could not
  independently re-verify. Never promoted to verified automatically.
- **partial** — collected before a delegation failure; may be incomplete.
- **unsupported** — file type outside the catalog; listed, not hashed.
- **missing-at-fingerprint** — present at stat, absent at sha256sum.

## Chain rules

- `chain_hash` of entry N is `SHA-256(sha256 || prev_chain_hash || sequence ||
  timestamp)`.
- Entry 0 has `prev_chain_hash: null`.
- Reordering or dropping any entry invalidates every subsequent `chain_hash`.
- The receipt's `chain_head` must equal the `chain_hash` of the highest-
  sequence entry.
