# Design Note: Event-Stream Custody Log

## Goal

Future-proof IP Sentinel's custody layer so storage backends can change without touching the hash-chain logic or public API.

## Core abstraction

```rust
pub trait EventStore: Send + Sync {
    fn append(&mut self, entry: SealedEntry) -> Result<u64>;
    fn read_from(&self, seq: u64) -> Result<Box<dyn Iterator<Item = Result<SealedEntry>> + '_>>;
    fn head(&self) -> Result<Option<ChainHead>>;
}
```

- `SealedEntry` — a custody entry whose hash is already computed and chain-linked. The store never recomputes hashes; it only persists and retrieves.
- `append` returns the assigned sequence number.
- `read_from` streams forward from a sequence for verification or replay.
- `head` returns the current top hash for outside anchoring.

## First backend

`FileEventStore` — the existing append-only file pattern. fsync on every append. One file per vault, entries as length-prefixed frames.

## Future backends (no API change)

- S3 / object store: each entry is one object, keyed by sequence. Head is a pointer object updated transactionally.
- Ledger / blockchain: entries anchored as transactions; the store becomes a read-through cache.

## Manifest versioning

Export format carries a `version` field (v1 today). `verify_vault` branches on it so old exports still validate against newer engines. Bump the version only when the layout changes incompatibly.

## Uliya layer

The skill package is a pure adapter: it calls into `ip-sentinel-core` and translates results to UGREEN's runtime format. No crypto lives in the skill layer. If UGREEN changes their skill API, only this adapter is rewritten.

## Non-goals

- No networking in core. Ever.
- No credentials. The store trait takes no auth parameters; backends that need them receive them at construction time outside the crate's hot path.
