package corrosion

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

// The inverse must reject truncation, extra fields, wrong ordinals/domains,
// and invalid typed values without changing original codec1 bytes.
func TestSourceCutDecoderStrict(t *testing.T) {
	row := Row{Values: []interface{}{int64(1), "a,b", "2026-10-15T00:00:00Z"}}
	good, err := encodeAutomationCutRecord("adoptions", 1, row)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeSourceCutRow(6, 1, good)
	if err != nil || decoded.Int64("generation") != 1 || decoded.String("imported_from") != "a,b" {
		t.Fatal(decoded, err)
	}
	again, err := encodeAutomationCutRecord("adoptions", 1, decoded)
	if err != nil || !bytes.Equal(again, good) {
		t.Fatal("codec69/1 bytes changed", err)
	}
	for n := 0; n < len(good); n++ {
		if _, err := decodeSourceCutRow(6, 1, good[:n]); err == nil {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	for _, raw := range [][]byte{append(bytes.Clone(good), 0, 0, 0, 1, 0), append([]byte("LVCUT\x02"), good[6:]...), append([]byte("LVCUT\x01\xff\xff\xff\xff"), good[10:]...)} {
		if _, err := decodeSourceCutRow(6, 1, raw); err == nil {
			t.Fatal("malformed/trailing frame accepted")
		}
	}
	if _, err := decodeSourceCutRow(6, 2, good); err == nil {
		t.Fatal("wrong ordinal accepted")
	}
	if _, err := decodeSourceCutRow(7, 1, good); err == nil {
		t.Fatal("wrong section accepted")
	}
	bad := bytes.Clone(good)
	binary.BigEndian.PutUint64(bad[23:31], 0)
	if _, err := decodeSourceCutRow(6, 1, bad); err == nil {
		t.Fatal("mutated typed frame accepted")
	}
}

// Variable SQL bodies must not be fetched when scalar lengths exceed bounds.
func TestSourceConfigLengthBeforeBody(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	if err := a.c.ExecOutOfProcessForTest(`UPDATE voter_configs SET certificate=? WHERE generation=1`, strings.Repeat("x", maxSourceCertificateBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { _, err := sourceReadConfig(ctx, tx, 1); return err }); err == nil {
		t.Fatal("oversized membership certificate read")
	}
}
