package merkle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	merkle "github.com/opskernel-io/go-merkle-audit-chain"
)

// TestNewAppender_ZeroGenesis verifies nil and zero-length seeds produce the same initial prevHash.
func TestNewAppender_ZeroGenesis(t *testing.T) {
	a1 := merkle.NewAppender(nil)
	a2 := merkle.NewAppender([]byte{})
	ch1, _ := a1.AppendRaw("event-1", []byte("hello"), 1000)
	ch2, _ := a2.AppendRaw("event-1", []byte("hello"), 1000)
	if hex.EncodeToString(ch1) != hex.EncodeToString(ch2) {
		t.Errorf("nil and empty genesis seed diverged: %x vs %x", ch1, ch2)
	}
}

// TestNewAppender_CustomGenesis verifies a non-zero genesis seed changes the chain root.
func TestNewAppender_CustomGenesis(t *testing.T) {
	seed := sha256.Sum256([]byte("opskern-external-v1:install-abc:example.com"))
	aDefault := merkle.NewAppender(nil)
	aSeeded := merkle.NewAppender(seed[:])

	ch1, _ := aDefault.AppendRaw("event-1", []byte("payload"), 1000)
	ch2, _ := aSeeded.AppendRaw("event-1", []byte("payload"), 1000)
	if hex.EncodeToString(ch1) == hex.EncodeToString(ch2) {
		t.Error("default and seeded genesis produced identical chain hashes — genesis seed had no effect")
	}
}

// TestAppendRaw_AppendHash_Equivalence verifies that AppendRaw and AppendHash produce
// the same chain hash when given the same content.
func TestAppendRaw_AppendHash_Equivalence(t *testing.T) {
	seed := make([]byte, 32)
	a1 := merkle.NewAppender(seed)
	a2 := merkle.NewAppender(seed)

	raw := []byte("event payload bytes")
	sum := sha256.Sum256(raw)

	chainRaw, contentRaw := a1.AppendRaw("event-xyz", raw, 9999)
	chainHash := a2.AppendHash("event-xyz", sum[:], 9999)

	if hex.EncodeToString(chainRaw) != hex.EncodeToString(chainHash) {
		t.Errorf("AppendRaw and AppendHash diverged: %x vs %x", chainRaw, chainHash)
	}
	if hex.EncodeToString(contentRaw) != hex.EncodeToString(sum[:]) {
		t.Errorf("AppendRaw returned wrong contentHash: got %x, want %x", contentRaw, sum[:])
	}
}

// TestVerifyStream_RoundTrip builds a chain via Appender and verifies it via VerifyStream.
func TestVerifyStream_RoundTrip(t *testing.T) {
	a := merkle.NewAppender(nil)
	var buf bytes.Buffer

	type entry struct {
		id  string
		raw []byte
		ts  int64
	}
	entries := []entry{
		{"e1", []byte("first event"), 1000},
		{"e2", []byte("second event"), 2000},
		{"e3", []byte("third event"), 3000},
	}

	prevHashHex := fmt.Sprintf("%064x", 0)
	for _, e := range entries {
		chainHash, contentHash := a.AppendRaw(e.id, e.raw, e.ts)
		row := merkle.Row{
			EventID:     e.id,
			ContentHash: hex.EncodeToString(contentHash),
			PrevHash:    prevHashHex,
			ChainHash:   hex.EncodeToString(chainHash),
			OccurredAt:  e.ts,
		}
		b, _ := json.Marshal(row)
		buf.Write(b)
		buf.WriteByte('\n')
		prevHashHex = hex.EncodeToString(chainHash)
	}

	if err := merkle.VerifyStream(&buf); err != nil {
		t.Errorf("VerifyStream: %v", err)
	}
}

// TestVerifyStream_TamperedChainHash verifies that VerifyStream detects chain tampering.
func TestVerifyStream_TamperedChainHash(t *testing.T) {
	a := merkle.NewAppender(nil)
	chainHash, contentHash := a.AppendRaw("e1", []byte("payload"), 1000)

	row := merkle.Row{
		EventID:     "e1",
		ContentHash: hex.EncodeToString(contentHash),
		PrevHash:    fmt.Sprintf("%064x", 0),
		ChainHash:   hex.EncodeToString(chainHash),
		OccurredAt:  1000,
	}

	// Tamper: flip the last byte of ChainHash.
	tampered := row.ChainHash[:len(row.ChainHash)-2] + "ff"
	row.ChainHash = tampered

	b, _ := json.Marshal(row)
	if err := merkle.VerifyStream(bytes.NewReader(b)); err == nil {
		t.Error("VerifyStream: expected error for tampered chain_hash, got nil")
	}
}

// TestVerifyStream_1000Entries verifies correctness at scale.
func TestVerifyStream_1000Entries(t *testing.T) {
	const n = 1000
	a := merkle.NewAppender(nil)
	var buf bytes.Buffer

	prevHashHex := fmt.Sprintf("%064x", 0)
	for i := range n {
		id := fmt.Sprintf("event-%05d", i)
		raw := []byte(fmt.Sprintf("payload-%d", i))
		ts := int64(i * 1000)

		chainHash, contentHash := a.AppendRaw(id, raw, ts)
		row := merkle.Row{
			EventID:     id,
			ContentHash: hex.EncodeToString(contentHash),
			PrevHash:    prevHashHex,
			ChainHash:   hex.EncodeToString(chainHash),
			OccurredAt:  ts,
		}
		b, _ := json.Marshal(row)
		buf.Write(b)
		buf.WriteByte('\n')
		prevHashHex = hex.EncodeToString(chainHash)
	}

	if err := merkle.VerifyStream(&buf); err != nil {
		t.Errorf("VerifyStream 1000 entries: %v", err)
	}
}

// TestVerifyStreamFrom_CustomGenesis verifies VerifyStreamFrom with a non-zero genesis seed.
func TestVerifyStreamFrom_CustomGenesis(t *testing.T) {
	seed := sha256.Sum256([]byte("test-genesis"))
	a := merkle.NewAppender(seed[:])
	var buf bytes.Buffer

	chainHash, contentHash := a.AppendRaw("e1", []byte("payload"), 1000)
	row := merkle.Row{
		EventID:     "e1",
		ContentHash: hex.EncodeToString(contentHash),
		PrevHash:    hex.EncodeToString(seed[:]),
		ChainHash:   hex.EncodeToString(chainHash),
		OccurredAt:  1000,
	}
	b, _ := json.Marshal(row)
	buf.Write(b)
	buf.WriteByte('\n')

	// VerifyStream (zero genesis) should fail — chain was built with a non-zero seed.
	if err := merkle.VerifyStream(bytes.NewReader(buf.Bytes())); err == nil {
		t.Error("VerifyStream with zero genesis should fail for non-zero genesis chain")
	}
	// VerifyStreamFrom with the correct seed should pass.
	if err := merkle.VerifyStreamFrom(bytes.NewReader(buf.Bytes()), seed[:]); err != nil {
		t.Errorf("VerifyStreamFrom with correct genesis: %v", err)
	}
}

// TestVerifyStream_NegativeOccurredAt verifies negative timestamps are rejected.
func TestVerifyStream_NegativeOccurredAt(t *testing.T) {
	// Build a row with negative occurred_at directly — Appender clamps to 0, so
	// we construct the JSON manually to test the verifier's guard.
	raw := `{"event_id":"e1","content_hash":"` +
		strings.Repeat("aa", 32) + `","prev_hash":"` +
		strings.Repeat("00", 32) + `","chain_hash":"` +
		strings.Repeat("bb", 32) + `","occurred_at":-1}`
	if err := merkle.VerifyStream(strings.NewReader(raw)); err == nil {
		t.Error("expected error for negative occurred_at")
	}
}
