# Capability Map

Maps every workflow step to a catalog action from the UGREEN AI NAS capability
catalog (Starter Kit, catalog 2.0.0). No invented capabilities.

| Step | Expert | CLI | Catalog action | Read/Write |
|------|--------|-----|---------------|------------|
| 1 Inventory | file-agent | ug-filesystem | find | Read |
| 2 Metadata | file-agent | ug-filesystem | stat | Read |
| 3 Fingerprint | file-agent | ug-filesystem | sha256sum | Read |
| 4a Image check | photo-agent | ug-photo | vision-ocr | Read |
| 4b Document check | document-agent | ug-document | extract | Read |
| 5 Chain assembly | (parent skill) | — | local computation | Read |
| 6 Labeling | (parent skill) | — | local computation | Read |
| 7 Receipt build | (parent skill) | — | local computation | Read |
| 8 Confirmation | (parent skill) | — | user interaction | — |
| 9a Save receipt | knowledge-agent | ug-knowledge | save-text | Write |
| 9b Output folder | file-agent | ug-filesystem | mkdir | Write |

## Design rules enforced by this map

- Every read step runs before any write step.
- The only writes are `save-text` (receipt) and `mkdir` (output folder), both
  gated on step 8 confirmation.
- `sha256sum` is the sole cryptographic primitive exposed by the NAS CLI; the
  Rust hash-chaining engine (Round 2) consumes these digests.
- No `cpmv`, no `rm`, no external network calls appear anywhere in the map.
