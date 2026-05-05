package merkle_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	merkle "github.com/opskernel-io/go-merkle-audit-chain"
)

// BenchmarkAppendRaw measures the hot path: hash chain extension from raw bytes.
func BenchmarkAppendRaw(b *testing.B) {
	a := merkle.NewAppender(nil)
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mcp__test__echo","arguments":{"msg":"hello"}}}`)
	b.ResetTimer()
	for i := range b.N {
		a.AppendRaw(fmt.Sprintf("event-%d", i), payload, int64(i*1000))
	}
}

// BenchmarkVerifyStream measures streaming verification throughput.
// Builds a 10 000-entry chain once, then benchmarks the verify pass.
func BenchmarkVerifyStream(b *testing.B) {
	const n = 10_000
	a := merkle.NewAppender(nil)
	var buf bytes.Buffer

	prevHashHex := fmt.Sprintf("%064x", 0)
	for i := range n {
		id := fmt.Sprintf("event-%06d", i)
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
		enc, _ := json.Marshal(row)
		buf.Write(enc)
		buf.WriteByte('\n')
		prevHashHex = hex.EncodeToString(chainHash)
	}
	data := buf.Bytes()

	b.ResetTimer()
	for range b.N {
		if err := merkle.VerifyStream(bytes.NewReader(data)); err != nil {
			b.Fatalf("VerifyStream: %v", err)
		}
	}
}
