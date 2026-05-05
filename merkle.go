// Package merkle implements an append-only audit chain with SHA-256 hash linking.
// It is extracted from hookd-core (github.com/opskernel-io/hookd) and has no
// storage coupling — callers supply and persist the Row values.
//
// Chain input domain: SHA-256(prev_hash ‖ event_id ‖ content_hash ‖ occurred_at_bigendian).
package merkle

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Row is a single chain entry for streaming verification.
// ContentHash, PrevHash, and ChainHash are lower-case hex-encoded SHA-256 values.
type Row struct {
	EventID     string `json:"event_id"`
	ContentHash string `json:"content_hash"`
	PrevHash    string `json:"prev_hash"`
	ChainHash   string `json:"chain_hash"`
	OccurredAt  int64  `json:"occurred_at"` // Unix milliseconds
}

// Appender builds a tamper-evident SHA-256 hash chain with no storage coupling.
// Safe for concurrent use.
type Appender struct {
	mu       sync.Mutex
	prevHash []byte
}

// NewAppender creates an Appender.
// genesisSeed, when non-nil and non-empty, is used as the initial prevHash.
// Nil or zero-length genesisSeed uses 32 zero bytes (default single-source chain root).
// For multi-source deployments pin the root via SHA-256("opskern-external-v1:" + installUUID + ":" + sourceFQDN).
func NewAppender(genesisSeed []byte) *Appender {
	a := &Appender{prevHash: make([]byte, 32)}
	if len(genesisSeed) > 0 {
		copy(a.prevHash, genesisSeed)
	}
	return a
}

// AppendRaw computes SHA-256(raw) internally and extends the chain.
// Returns (chainHash, contentHash). Store both alongside the raw event.
// eventID must be unique across all entries in this chain.
func (a *Appender) AppendRaw(eventID string, raw []byte, occurredAtMs int64) (chainHash, contentHash []byte) {
	sum := sha256.Sum256(raw)
	chain := a.AppendHash(eventID, sum[:], occurredAtMs)
	return chain, sum[:]
}

// AppendHash extends the chain using a caller-supplied contentHash.
// Use AppendRaw unless content bytes are unavailable at call time (e.g. the caller streamed
// the content and computed the hash externally). contentHash must be SHA-256 of the raw event
// bytes; the chain links it without re-verifying that invariant.
func (a *Appender) AppendHash(eventID string, contentHash []byte, occurredAtMs int64) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()

	if occurredAtMs < 0 {
		occurredAtMs = 0 // chain hash treats timestamp as unsigned; clamp at call boundary
	}
	h := sha256.New()
	h.Write(a.prevHash)
	h.Write([]byte(eventID))
	h.Write(contentHash)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(occurredAtMs)) //nolint:gosec // G115: clamped to ≥0 above
	h.Write(tsBuf[:])
	chain := h.Sum(nil)
	copy(a.prevHash, chain)
	return chain
}

// VerifyStream verifies a chain of Row values from r.
// Each non-empty line of r must be a JSON-encoded Row (JSON lines format).
// Memory usage is O(1) regardless of chain size.
// Starts from 32 zero bytes (the default genesis); for non-zero genesis chains use VerifyStreamFrom.
// Returns the first verification error including entry index and expected vs. actual hash.
func VerifyStream(r io.Reader) error {
	return VerifyStreamFrom(r, nil)
}

// VerifyStreamFrom is like VerifyStream but starts from genesisSeed as the initial prevHash.
// Nil or zero-length genesisSeed is equivalent to VerifyStream.
func VerifyStreamFrom(r io.Reader, genesisSeed []byte) error {
	prevHash := make([]byte, 32)
	if len(genesisSeed) > 0 {
		copy(prevHash, genesisSeed)
	}

	scanner := bufio.NewScanner(r)
	idx := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var row Row
		if err := json.Unmarshal(line, &row); err != nil {
			return fmt.Errorf("merkle: VerifyStream entry %d: parse: %w", idx, err)
		}
		if row.OccurredAt < 0 {
			return fmt.Errorf("merkle: VerifyStream entry %d (%s): negative occurred_at", idx, row.EventID)
		}
		contentHash, err := hex.DecodeString(row.ContentHash)
		if err != nil {
			return fmt.Errorf("merkle: VerifyStream entry %d (%s): decode content_hash: %w", idx, row.EventID, err)
		}
		storedChain, err := hex.DecodeString(row.ChainHash)
		if err != nil {
			return fmt.Errorf("merkle: VerifyStream entry %d (%s): decode chain_hash: %w", idx, row.EventID, err)
		}

		h := sha256.New()
		h.Write(prevHash)
		h.Write([]byte(row.EventID))
		h.Write(contentHash)
		var tsBuf [8]byte
		binary.BigEndian.PutUint64(tsBuf[:], uint64(row.OccurredAt)) //nolint:gosec // G115: guard above ensures non-negative
		h.Write(tsBuf[:])
		expected := h.Sum(nil)

		if hex.EncodeToString(expected) != hex.EncodeToString(storedChain) {
			return fmt.Errorf("merkle: VerifyStream entry %d (%s): chain broken: expected %s, got %s",
				idx, row.EventID,
				hex.EncodeToString(expected),
				hex.EncodeToString(storedChain),
			)
		}
		prevHash = storedChain
		idx++
	}
	return scanner.Err()
}
