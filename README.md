# go-merkle-audit-chain

Append-only audit chain with SHA-256 hash linking. No storage coupling — the library computes hashes; you store the rows.

Extracted from [hookd](https://github.com/opskernel-io/hookd). Designed for EU AI Act Article 12 audit log integrity.

## Installation

```
go get github.com/opskernel-io/go-merkle-audit-chain@latest
```

Requires Go 1.21+. No external dependencies.

## Quick Start

```go
import merkle "github.com/opskernel-io/go-merkle-audit-chain"

// Build a chain
a := merkle.NewAppender(nil) // nil = 32 zero bytes genesis

chainHash, contentHash := a.AppendRaw("event-001", rawEventBytes, time.Now().UnixMilli())
// Store chainHash, contentHash, prevHash alongside your raw event row.

// Verify a chain (JSON lines, one Row per line, ordered by rowid)
err := merkle.VerifyStream(rowsReader)
```

For multi-source deployments, namespace the chain root:

```go
seed := sha256.Sum256([]byte("opskern-external-v1:" + installUUID + ":" + sourceFQDN))
a := merkle.NewAppender(seed[:])
// Verify with the matching seed:
err := merkle.VerifyStreamFrom(rowsReader, seed[:])
```

## API

### Types

```go
type Row struct {
    EventID     string `json:"event_id"`
    ContentHash string `json:"content_hash"` // hex SHA-256 of raw event bytes
    PrevHash    string `json:"prev_hash"`     // hex SHA-256; previous chain_hash
    ChainHash   string `json:"chain_hash"`    // hex SHA-256; this entry's chain hash
    OccurredAt  int64  `json:"occurred_at"`   // Unix milliseconds
}
```

### Appender

```go
func NewAppender(genesisSeed []byte) *Appender
```
Creates an Appender. `nil` or zero-length `genesisSeed` uses 32 zero bytes. For multi-source chains, supply a per-source seed.

```go
func (a *Appender) AppendRaw(eventID string, raw []byte, occurredAtMs int64) (chainHash, contentHash []byte)
```
Recommended path. Computes `SHA-256(raw)` internally, extends the chain. Returns both hashes for storage.

```go
func (a *Appender) AppendHash(eventID string, contentHash []byte, occurredAtMs int64) []byte
```
Extends the chain with a pre-computed `contentHash`. Use only when raw bytes are unavailable (e.g. streaming ingestion with external hash computation). The caller is responsible for the SHA-256 invariant.

### Verification

```go
func VerifyStream(r io.Reader) error
func VerifyStreamFrom(r io.Reader, genesisSeed []byte) error
```
Reads JSON lines from `r` (one `Row` per line, ordered by `rowid` ascending). O(1) memory. Returns the first broken link, including row index and expected vs. actual hash, or `nil` if the chain is intact.

Use `VerifyStreamFrom` for non-zero genesis chains.

## Chain construction

Each chain hash commits to its entire prior history:

```
chain_hash[n] = SHA-256(chain_hash[n-1] ‖ event_id ‖ content_hash ‖ occurred_at_bigendian_uint64)
```

`chain_hash[0]` uses the genesis seed (32 zero bytes by default) as `chain_hash[-1]`.

## Security Properties

### Hash function

The chain uses **SHA-256** throughout: content hashes, chain hashes, genesis seeds, and monthly digest roots. SHA-256 provides second-preimage resistance (~2^256): given a chain_hash, an attacker cannot construct different inputs (`prev_hash ‖ event_id ‖ content_hash ‖ occurred_at`) that produce the same hash. SHA-256 also has no known practical collisions. Callers must not substitute weaker algorithms — the verification contract assumes SHA-256 at every step.

When using `AppendHash`, the library does not verify that the provided `content_hash` is SHA-256 of the event bytes. Callers bear full responsibility for this invariant. `AppendRaw` is the recommended path — it computes SHA-256 internally.

### What the chain guarantees

- **Append-only ordering.** Each chain hash commits to the entire prior history. A row cannot be inserted before an existing row without invalidating every subsequent chain hash.
- **Tamper-evidence for stored rows.** Any post-write modification to an event's `event_id`, `content_hash`, or `occurred_at_ms` will cause `VerifyStream` to return an error at that row. Any deletion of an interior row breaks the chain at the next extant row.
- **Independent auditability.** A third party with read access to the stored rows can run `VerifyStream` without trusting the chain operator. No secret key is required to verify.

### What the chain does NOT guarantee

- **Non-repudiation against a compromised storage layer.** This library detects accidental corruption and provides evidence of tampering by privileged insiders, but does not prevent an attacker with full database write access from rewriting the chain. A full chain rewrite produces a syntactically valid chain that `VerifyStream` will accept. For non-repudiation against a compromised storage layer, combine with RFC 3161 timestamping (see [writ](https://writ.opskernel.io)).
- **Timestamp authority.** `occurred_at_ms` is caller-supplied. The library does not validate it against a trusted clock. A malicious appender can write any timestamp value.
- **Legal non-repudiation (eIDAS).** The chain alone does not satisfy eIDAS requirements. EU AI Act Article 12 non-repudiation requires RFC 3161 timestamp tokens from a qualified TSA — this is a writ product feature, not provided by this library.
- **Protection against a compromised appender.** An attacker who controls the process writing to the chain can append fabricated events. The chain proves ordering and integrity of what was written; it does not prove that what was written is genuine.

### Genesis seed

The genesis seed (`genesisSeed`) is the 32-byte value used as `prev_hash` for the first event. It namespaces the chain root — two chains with different genesis seeds are structurally independent even if they contain identical events.

**Attacker control of genesis seed:** If an attacker substitutes a chain rooted at a different genesis seed, the replacement chain is syntactically valid but does not link to the original root. Verifiers who store and compare the expected genesis seed out-of-band will detect this; verifiers who accept any genesis seed will not. Callers are responsible for persisting and checking the expected genesis seed independently.

### Threat model

| Attack | Detected? | Notes |
|--------|-----------|-------|
| Post-hoc modification of a stored row | **Yes** | `VerifyStream` returns error at modified row |
| Deletion of an interior row | **Yes** | Chain break at next extant row |
| Truncation (deletion of trailing rows) | **No** | Caller must record expected row count / latest chain hash out-of-band |
| Full chain rewrite by a DB-level attacker | **No** | Replacement chain is syntactically valid; RFC 3161 timestamps required |
| Genesis seed substitution | **No** (unless caller pins seed) | See genesis seed section above |
| Fabricated events by a compromised appender | **No** | Chain proves ordering, not event authenticity |

### Audit verification

`VerifyStream(r io.Reader) error` is the primary audit path. It:

- Reads JSON lines, consuming one row at a time — O(1) memory regardless of chain length
- Re-derives each `chain_hash` from stored inputs
- Returns the first row where the re-derived hash does not match the stored value, or `nil` if the chain is intact

A third party can audit a chain without operator cooperation by: (1) obtaining a read-only row export in `rowid` order, (2) encoding each row as a JSON line (`Row` struct), (3) calling `VerifyStream`. No keys, no network access, no operator trust required.

### Known limitations (v0.1)

- **No timestamp authority.** `occurred_at_ms` is not externally verified. RFC 3161 timestamping is on the roadmap via writ integration (targeted v0.2).
- **No truncation detection.** Callers must independently persist the expected final chain hash (and row count) to detect truncation. `VerifyStream` returns nil on a truncated chain if the remaining rows are internally consistent — it cannot know rows are missing.
- **No cross-chain linking.** Independent chains (first-party and external OTLP) are not cryptographically linked. An operator with full DB access could swap chain segments between sources without breaking individual chain verification.
- **No signing keys.** The library has no concept of signing keys or appender identity. Appender authenticity requires external controls (process isolation, OS audit logs, HSM) — not provided by this library.
- **No algorithm agility (v0.1).** SHA-256 is hardcoded. Migration to a different hash algorithm would require full chain re-computation. Account for this if audit chains are expected to span multi-year retention windows.

## License

Apache 2.0. See [LICENSE](LICENSE). An explicit patent grant is provided in [PATENTS](PATENTS).

## Contributing

Open an issue. PRs welcome.
