# Validation Plan

Two core test cases and one edge case. Designed for Finalist NAS access;
Round 1 judges evaluate from this plan plus the SKILL.md.

## Core case 1: Happy path seal

1. Place five known files (two images, two documents, one text) in a test
   folder on the NAS.
2. Run IP Sentinel on that folder.
3. Expect: five entries, all labeled `verified`, chain intact, receipt saved
   after one confirmation, `chain_head` reported.

## Core case 2: Tamper detection

1. Seal a folder as in case 1.
2. Modify one file's bytes (append a single character).
3. Re-run verification.
4. Expect: that entry's digest no longer matches, label flips from `verified`
   to a mismatch flag, chain break reported at its sequence number, export
   blocked until the operator acknowledges.

## Edge case: Empty or unsupported folder

1. Run IP Sentinel on a folder containing only an unsupported type (e.g., a
   binary with no catalog action) or an empty folder.
2. Expect: clear "no supported files found" or an `unsupported` list — never
   a silent pass, never a substituted result, never a crash.
