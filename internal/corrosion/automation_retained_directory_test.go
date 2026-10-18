package corrosion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func retainedDescriptorInput(kind string) retainedObjectDescriptor {
	d := strings.Repeat("a", 64)
	out := retainedObjectDescriptor{1, kind, retainedObjectLayout(kind), d, "original", "original-inc", nil}
	sections := []string{kind + "/v1"}
	if kind == "local" {
		sections = nil
		for _, table := range aggregateLocalTables() {
			sections = append(sections, table.descriptor().name)
		}
	}
	for _, section := range sections {
		h := sha256.New()
		if kind == "local" {
			frame, _ := automationCutFrame("section/v1", []byte(section))
			h.Write(frame)
			out.ComponentInventories = append(out.ComponentInventories, automationCutInventory{section, 1, 0, 0, hex.EncodeToString(h.Sum(nil))})
		} else {
			h.Write([]byte("x"))
			out.ComponentInventories = append(out.ComponentInventories, automationCutInventory{section, 1, 1, 1, hex.EncodeToString(h.Sum(nil))})
		}
	}
	return out
}

func TestRetainedObjectClosedInventory(t *testing.T) {
	v := retainedDescriptorInput("local")
	raw, _ := json.Marshal(v)
	got, err := decodeRetainedObject(raw)
	if err != nil {
		t.Fatalf("complete authenticated empty local inventory refused: %v", err)
	}
	if len(got.ComponentInventories) != len(aggregateLocalTables()) {
		t.Fatal("local inventory lost empty table terminals")
	}
	for name, mutate := range map[string]func(*retainedObjectDescriptor){
		"unknown-kind":   func(v *retainedObjectDescriptor) { v.Kind = "caller-sql" },
		"unknown-layout": func(v *retainedObjectDescriptor) { v.LayoutDigest = strings.Repeat("b", 64) },
		"missing-empty-table": func(v *retainedObjectDescriptor) {
			v.ComponentInventories = v.ComponentInventories[:len(v.ComponentInventories)-1]
		},
		"extra-table": func(v *retainedObjectDescriptor) {
			v.ComponentInventories = append(v.ComponentInventories, v.ComponentInventories[0])
		},
		"reorder": func(v *retainedObjectDescriptor) {
			v.ComponentInventories[0], v.ComponentInventories[1] = v.ComponentInventories[1], v.ComponentInventories[0]
		},
		"codec":            func(v *retainedObjectDescriptor) { v.ComponentInventories[0].Codec++ },
		"empty-hash":       func(v *retainedObjectDescriptor) { v.ComponentInventories[0].Digest = strings.Repeat("b", 64) },
		"negative-records": func(v *retainedObjectDescriptor) { v.ComponentInventories[0].Records = -1 },
		"negative-bytes":   func(v *retainedObjectDescriptor) { v.ComponentInventories[0].Bytes = -1 },
		"overflow": func(v *retainedObjectDescriptor) {
			for i := 0; i < 2; i++ {
				v.ComponentInventories[i].Records = math.MaxInt64
				v.ComponentInventories[i].Bytes = math.MaxInt64
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := v
			copy.ComponentInventories = append([]automationCutInventory(nil), v.ComponentInventories...)
			mutate(&copy)
			raw, _ := json.Marshal(copy)
			if _, err := decodeRetainedObject(raw); err == nil {
				t.Fatal("invalid local descriptor accepted")
			}
		})
	}
}

func TestRetainedDirectoryReceiptNotCircular(t *testing.T) {
	build := func(receipt string) (string, string, int64, int64, int64, int64, error) {
		var d retainedDirectoryDigest
		for i, kind := range []string{"header", "receipt", "binding", "local"} {
			v := retainedDescriptorInput(kind)
			if kind == "receipt" {
				v.OriginalIdentity = receipt
			}
			raw, _ := json.Marshal(v)
			if err := d.add(int64(i+1), raw); err != nil {
				return "", "", 0, 0, 0, 0, err
			}
		}
		return d.finish()
	}
	d, g, n, en, b, eb, err := build(strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("typed complete directory refused: %v", err)
	}
	d2, g2, n2, en2, b2, eb2, err := build(strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if d == d2 || g != g2 || n != 4 || en != 3 || n2 != n || en2 != en || b != 3 || eb != 2 || b2 != b || eb2 != eb {
		t.Fatal("receipt introduced graph cycle or escaped complete directory commitment")
	}
	var out retainedDirectoryDigest
	raw, _ := json.Marshal(retainedDescriptorInput("header"))
	if err := out.add(2, raw); err == nil {
		t.Fatal("directory ordinal gap accepted")
	}
	if _, _, _, _, _, _, err := out.finish(); err == nil {
		t.Fatal("empty/missing receipt directory accepted")
	}
}
