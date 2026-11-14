# Third-Party Disclosure

## Components

- **UGOS Skill Creation Tool / uliya-skill-kit 0.7.3** — UGREEN Hackathon
  Starter Kit (https://ai.ugreen.com/pages/hackathon-starter-kit). Used to
  author and statically validate this skill. Not bundled in the submission ZIP.
- **UGREEN AI NAS CLI capabilities** — ug-filesystem, ug-photo, ug-document,
  ug-knowledge. Platform-provided; no separate license.

## AI tools used

- Large language model assistance for drafting SKILL.md prose and reference
  structure during development. Principal use: workflow authoring and
  documentation. No model is called at runtime by this skill; all execution
  uses the NAS's registered expert agents and local CLI.

## Principal functionality developed for this hackathon

- The IP Sentinel custody workflow: inventory, SHA-256 fingerprinting,
  content cross-check, hash-chained log, claimed-versus-verified labeling,
  versioned export receipt, and confirmation-gated writes.
- The Round 2 Rust engine (separate repository, gendynamics/ip-sentinel) that
  will perform the actual hash chaining and chain-break detection on NAS
  hardware. Not included in this Round 1 package per submission rules.

## Data handling

- All hashing and chaining occur locally on the NAS.
- No file content, digests, or metadata leave the device.
- No credentials, API keys, or personal data are included in this package.
- Placeholders are used for any configuration examples.
