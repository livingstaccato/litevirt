package corrosion

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// These are consumed metadata fixtures, never evidence of a completed import.
func retainedReceiptInput() retainedImportReceipt {
	d := strings.Repeat("a", 64)
	return retainedImportReceipt{1, "automation-completed-import", "holder", "inc-holder", 2,
		d, d, d, d, d, d, d, d, 7, 2048, d, d}
}

func TestRetainedReceiptCanonicalMetadata(t *testing.T) {
	want := retainedReceiptInput()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRetainedReceipt(raw)
	if err != nil {
		t.Fatalf("canonical consumed receipt refused: %v", err)
	}
	if got != want {
		t.Fatal("receipt fields changed")
	}
	if sourceDigest([]byte(retainedReceiptDomain), raw) == sourceDigest(raw) {
		t.Fatal("receipt digest lost domain separation")
	}
	for name, mutate := range map[string]func(*retainedImportReceipt){
		"version":           func(v *retainedImportReceipt) { v.Version++ },
		"purpose":           func(v *retainedImportReceipt) { v.Purpose = "automation-membership-source" },
		"host-empty":        func(v *retainedImportReceipt) { v.Host = "" },
		"host-bound":        func(v *retainedImportReceipt) { v.Host = strings.Repeat("x", 254) },
		"incarnation-bound": func(v *retainedImportReceipt) { v.Incarnation = strings.Repeat("x", 129) },
		"generation":        func(v *retainedImportReceipt) { v.Generation = 0 },
		"attempt":           func(v *retainedImportReceipt) { v.Attempt = strings.Repeat("A", 64) },
		"graph":             func(v *retainedImportReceipt) { v.EvidenceGraphRoot = "bad" },
		"objects":           func(v *retainedImportReceipt) { v.EvidenceObjects = 0 },
		"bytes":             func(v *retainedImportReceipt) { v.EvidenceBytes = -1 },
		"claims":            func(v *retainedImportReceipt) { v.ClaimsDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v := want
			mutate(&v)
			b, _ := json.Marshal(v)
			if _, err := decodeRetainedReceipt(b); err == nil {
				t.Fatal("malformed receipt accepted")
			}
		})
	}
	for name, malformed := range map[string][]byte{
		"whitespace":   append([]byte(" "), raw...),
		"duplicate":    bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Version":1,"Version":1`), 1),
		"unknown":      bytes.Replace(raw, []byte(`"Version":1`), []byte(`"Unused":true,"Version":1`), 1),
		"overflow":     bytes.Replace(raw, []byte(`"EvidenceBytes":2048`), []byte(`"EvidenceBytes":9223372036854775808`), 1),
		"nul":          bytes.Replace(raw, []byte(`"holder"`), []byte(`"holder\u0000"`), 1),
		"over-bound":   bytes.Repeat([]byte(" "), maxRetainedReceiptBytes+1),
		"invalid-utf8": bytes.Replace(raw, []byte("holder"), []byte{0xff}, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRetainedReceipt(malformed); err == nil {
				t.Fatal("noncanonical receipt accepted")
			}
		})
	}
}

func TestRetainedStorageNamespaceClosedBound(t *testing.T) {
	d := strings.Repeat("b", 64)
	for _, ordinal := range []int64{0, 1, math.MaxInt64} {
		ns, err := retainedNamespace(d, ordinal)
		if err != nil {
			t.Fatalf("valid closed address refused: %v", err)
		}
		if !strings.HasPrefix(ns, "retained-v1:"+d+":") || len(ns) > 96 || receiverDigest(ns) {
			t.Fatal("supplemental address crossed authentication ID boundary")
		}
		if ordinal == math.MaxInt64 && len(ns) != 96 {
			t.Fatalf("maximum address length = %d", len(ns))
		}
	}
	for _, d := range []string{"", strings.Repeat("B", 64), strings.Repeat("b", 65), strings.Repeat("g", 64)} {
		if _, err := retainedNamespace(d, 0); err == nil {
			t.Fatal("noncanonical delivery ID accepted")
		}
	}
	if _, err := retainedNamespace(strings.Repeat("b", 64), -1); err == nil {
		t.Fatal("negative ordinal accepted")
	}
}
