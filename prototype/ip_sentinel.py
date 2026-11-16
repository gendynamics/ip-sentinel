"""IP Sentinel: a local, tamper-evident custody log for intellectual-property files.

Each commit records the SHA-256 of every file in a workspace into a block that is
hash-linked to the previous block. Changing any recorded hash, timestamp, author,
or the order of blocks breaks the chain, and verify_integrity() reports it.

Limitation: timestamps come from the local clock, and anyone who can write to the
storage directory can rebuild the entire chain from scratch. To make a timestamp
credible to a third party, anchor the head block hash with an independent witness
(an RFC 3161 timestamp authority, OpenTimestamps, a notary, etc.).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

FORMAT_VERSION = 1
GENESIS_PREVIOUS_HASH = "0" * 64
CHAIN_FILE_NAME = "custody_chain.json"

_CHUNK_SIZE = 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

VERIFICATION_METHOD = [
    "For each block, drop the 'block_hash' field and serialize the rest as JSON "
    "with sorted keys, separators (',', ':'), UTF-8 encoding and non-ASCII characters left unescaped.",
    "The SHA-256 hex digest of those bytes must equal the block's 'block_hash'.",
    "Block 0's 'previous_block_hash' is 64 zeros; every later block's must equal the prior block's 'block_hash'.",
    "To prove a file's contents existed by a block's timestamp, compute the file's SHA-256 "
    "and find it in that block's 'entries'.",
]

TIMESTAMP_CAVEAT = (
    "Timestamps come from the committing machine's clock. Anchor head_block_hash with an "
    "independent timestamping service to make them verifiable by a third party."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_block_hash(block: dict) -> str:
    """SHA-256 of the block's canonical JSON, excluding its own block_hash field."""
    body = {k: v for k, v in block.items() if k != "block_hash"}
    return hashlib.sha256(_canonical_json(body)).hexdigest()


def hash_file(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _change_status(previous_hash: str | None, current_hash: str) -> str:
    if previous_hash is None:
        return "new"
    return "unchanged" if previous_hash == current_hash else "modified"


@dataclass
class IntegrityReport:
    valid: bool
    blocks_checked: int
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid

    def __str__(self) -> str:
        if self.valid:
            return f"PASS - {self.blocks_checked} block(s) verified, chain intact"
        return f"FAIL - {'; '.join(self.errors)}"

    def to_dict(self) -> dict:
        return {"valid": self.valid, "blocks_checked": self.blocks_checked, "errors": list(self.errors)}


def verify_blocks(blocks: Iterable[Any]) -> IntegrityReport:
    """Check every block's hash and its link to the previous block."""
    errors: list[str] = []
    expected_previous = GENESIS_PREVIOUS_HASH
    count = 0
    for position, block in enumerate(blocks):
        count += 1
        label = f"block {position}"
        if not isinstance(block, dict):
            errors.append(f"{label}: not a JSON object")
            expected_previous = None
            continue
        if block.get("index") != position:
            errors.append(f"{label}: index is {block.get('index')!r}, expected {position}")
        if block.get("previous_block_hash") != expected_previous:
            target = "genesis marker" if position == 0 else f"block {position - 1}'s hash"
            errors.append(f"{label}: previous_block_hash does not match {target}")
        if block.get("block_hash") != compute_block_hash(block):
            errors.append(f"{label}: contents were altered (block_hash mismatch)")
        # Link the next block to the stored hash so one altered block yields one error.
        expected_previous = block.get("block_hash")
    return IntegrityReport(valid=not errors, blocks_checked=count, errors=errors)


def verify_package(package: dict) -> IntegrityReport:
    """Verify an exported package on its own, without access to the original ledger."""
    blocks = package.get("blocks")
    if not isinstance(blocks, list):
        return IntegrityReport(valid=False, blocks_checked=0, errors=["package has no 'blocks' list"])
    report = verify_blocks(blocks)
    head = blocks[-1].get("block_hash") if blocks and isinstance(blocks[-1], dict) else None
    if package.get("head_block_hash") != head:
        report.errors.append("head_block_hash does not match the last block")
        report.valid = False
    return report


class IPSentinel:
    """Scans a workspace, commits file hashes to a hash-linked ledger, and exports proofs."""

    def __init__(self, storage_dir: str | os.PathLike = "./sentinel_data") -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.chain_path = self.storage_dir / CHAIN_FILE_NAME

    # -- storage ---------------------------------------------------------------

    def _load_chain(self) -> list:
        """Read the ledger from disk; disk is the single source of truth."""
        if not self.chain_path.exists():
            return []
        with self.chain_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        blocks = data.get("blocks") if isinstance(data, dict) else None
        if not isinstance(blocks, list):
            raise ValueError(f"{self.chain_path} is not a valid IP Sentinel ledger")
        return blocks

    def _save_chain(self, chain: list) -> None:
        payload = {"format_version": FORMAT_VERSION, "blocks": chain}
        fd, tmp_name = tempfile.mkstemp(dir=self.storage_dir, prefix=".chain-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.chain_path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise

    @staticmethod
    def _latest_known_hashes(chain: list) -> dict[str, str]:
        known: dict[str, str] = {}
        for block in chain:
            for entry in block.get("entries", []):
                known[entry["relative_path"]] = entry["sha256_hash"]
        return known

    # -- public API ------------------------------------------------------------

    def get_chain(self) -> list:
        """Return the ledger's blocks as stored on disk, oldest first."""
        return self._load_chain()

    def find_file_hash(self, sha256_hash: str) -> list[dict]:
        """Return every committed entry whose SHA-256 equals `sha256_hash`, oldest first."""
        target = sha256_hash.strip().lower()
        matches = []
        for block in self._load_chain():
            for entry in block.get("entries", []):
                if entry.get("sha256_hash") == target:
                    matches.append({
                        "block_index": block.get("index"),
                        "timestamp": block.get("timestamp"),
                        "author": block.get("author"),
                        "block_hash": block.get("block_hash"),
                        "relative_path": entry.get("relative_path"),
                        "status": entry.get("status"),
                    })
        return matches

    def scan_and_discover(self, directory: str | os.PathLike) -> list[dict]:
        """Hash every regular file under `directory`.

        Each result is labelled 'new', 'modified' or 'unchanged' relative to the latest
        committed hash for the same relative path. Hidden files and directories (such as
        .DS_Store or .git), symlinks, and this sentinel's own storage directory are skipped.
        """
        root = Path(directory).resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")
        storage = self.storage_dir.resolve()
        known = self._latest_known_hashes(self._load_chain())

        results: list[dict] = []
        for dirpath, dirnames, filenames in os.walk(root):
            current = Path(dirpath)
            dirnames[:] = sorted(
                d for d in dirnames if not d.startswith(".") and (current / d).resolve() != storage
            )
            for name in filenames:
                path = current / name
                if name.startswith(".") or path.is_symlink() or not path.is_file():
                    continue
                relative_path = path.relative_to(root).as_posix()
                digest = hash_file(path)
                stat = path.stat()
                results.append({
                    "file_name": name,
                    "relative_path": relative_path,
                    "sha256_hash": digest,
                    "size_bytes": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    "status": _change_status(known.get(relative_path), digest),
                })
        results.sort(key=lambda entry: entry["relative_path"])
        return results

    def commit_custody_log(self, scan_results: list[dict], author: str) -> dict:
        """Append a block recording `scan_results` and return it.

        Refuses to extend a ledger that fails verification, so a tampered history
        never gets new blocks built on top of it.
        """
        if not scan_results:
            raise ValueError("Nothing to commit: scan_results is empty")
        if not author or not author.strip():
            raise ValueError("author is required")

        chain = self._load_chain()
        report = verify_blocks(chain)
        if not report:
            raise RuntimeError(f"Refusing to commit to a ledger that fails verification: {report}")

        known = self._latest_known_hashes(chain)
        entries = []
        seen_paths: set[str] = set()
        for item in sorted(scan_results, key=lambda entry: entry["relative_path"]):
            relative_path = item["relative_path"]
            digest = item["sha256_hash"]
            if relative_path in seen_paths:
                raise ValueError(f"Duplicate entry for {relative_path!r}")
            if not isinstance(digest, str) or not _SHA256_RE.match(digest):
                raise ValueError(f"Invalid SHA-256 hash for {relative_path!r}: {digest!r}")
            seen_paths.add(relative_path)
            entries.append({
                "file_name": item["file_name"],
                "relative_path": relative_path,
                "sha256_hash": digest,
                "size_bytes": item.get("size_bytes"),
                "modified_at": item.get("modified_at"),
                "status": _change_status(known.get(relative_path), digest),
            })

        block = {
            "index": len(chain),
            "timestamp": _utc_now(),
            "author": author.strip(),
            "previous_block_hash": chain[-1]["block_hash"] if chain else GENESIS_PREVIOUS_HASH,
            "file_count": len(entries),
            "entries": entries,
        }
        block["block_hash"] = compute_block_hash(block)
        chain.append(block)
        self._save_chain(chain)
        return block

    def verify_integrity(self) -> IntegrityReport:
        """Re-read the ledger from disk and check every hash and link."""
        try:
            chain = self._load_chain()
        except (OSError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
            return IntegrityReport(valid=False, blocks_checked=0, errors=[f"ledger unreadable: {exc}"])
        return verify_blocks(chain)

    def generate_verification_package(self, output_path: str | os.PathLike | None = None) -> dict:
        """Build a self-contained proof that a third party can check with verify_package()."""
        chain = self._load_chain()
        package = {
            "package_type": "ip-sentinel-verification",
            "format_version": FORMAT_VERSION,
            "generated_at": _utc_now(),
            "hash_algorithm": "SHA-256",
            "integrity": verify_blocks(chain).to_dict(),
            "chain_length": len(chain),
            "head_block_hash": chain[-1]["block_hash"] if chain else None,
            "verification_method": VERIFICATION_METHOD,
            "timestamp_caveat": TIMESTAMP_CAVEAT,
            "blocks": chain,
        }
        if output_path is not None:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(package, f, indent=2, ensure_ascii=False)
        return package
