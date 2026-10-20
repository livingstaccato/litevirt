package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// Consumed-format cases only: no synthetic layout test establishes custody,
// current authority or a completed historical import. Real83 fixture is separate.
func TestRetainedOriginal83LayoutDispatch(t *testing.T) {
	old := aggregateLocalTables83()
	current := aggregateLocalTables()
	if retainedLocalLayout83Digest() != "dad4d14693e2ba5b6637571a8a80f6ba3c37bf55094ff2be92dfae26bbb36b1a" {
		t.Fatal("RETAINED83_ARCHIVED_LAYOUT_BYTES_CHANGED")
	}
	if len(old) != 31 || len(current) != 33 || old[29].table != "local_automation_lifetimes" || old[30].table != "local_automation_credential_issuance" || current[29].table != "local_automation_target_operations" || current[30].table != "local_automation_target_reservations" {
		t.Fatal("RETAINED83_SECTION_SHIFT")
	}
	if retainedLocalLayout83Digest() == retainedLocalLayoutDigest() {
		t.Fatal("RETAINED83_LAYOUT_RELABELED")
	}
	for _, which := range []string{"old83", "current84"} {
		t.Run(which, func(t *testing.T) {
			d := retainedDescriptorInput("local")
			if which == "old83" {
				d.LayoutDigest = retainedLocalLayout83Digest()
				d.ComponentInventories = nil
				for _, table := range old {
					h := sha256.New()
					prefix, _ := automationCutFrame("section/v1", []byte(table.descriptor().name))
					h.Write(prefix)
					d.ComponentInventories = append(d.ComponentInventories, automationCutInventory{table.descriptor().name, 1, 0, 0, hex.EncodeToString(h.Sum(nil))})
				}
			}
			raw, _ := json.Marshal(d)
			decoded, err := decodeRetainedObject(raw)
			if err != nil {
				t.Fatal("RETAINED83_VALID_LAYOUT_REFUSED", err)
			}
			layouts, err := retainedLocalTablesForDigest(decoded.LayoutDigest)
			if err != nil || len(layouts) != len(d.ComponentInventories) {
				t.Fatal("RETAINED83_LAYOUT_CONTEXT", err)
			}
			for _, mutate := range []func(*retainedObjectDescriptor){
				func(v *retainedObjectDescriptor) { v.LayoutDigest = strings.Repeat("f", 64) },
				func(v *retainedObjectDescriptor) {
					v.ComponentInventories = v.ComponentInventories[:len(v.ComponentInventories)-1]
				},
				func(v *retainedObjectDescriptor) {
					v.ComponentInventories = append(v.ComponentInventories, v.ComponentInventories[0])
				},
				func(v *retainedObjectDescriptor) {
					v.ComponentInventories = append([]automationCutInventory(nil), v.ComponentInventories...)
					v.ComponentInventories[29], v.ComponentInventories[30] = v.ComponentInventories[30], v.ComponentInventories[29]
				},
				func(v *retainedObjectDescriptor) {
					if which == "old83" {
						v.LayoutDigest = retainedLocalLayoutDigest()
					} else {
						v.LayoutDigest = retainedLocalLayout83Digest()
					}
				},
			} {
				bad := d
				mutate(&bad)
				raw, _ := json.Marshal(bad)
				if _, err := decodeRetainedObject(raw); err == nil {
					t.Fatal("RETAINED83_MALFORMED_LAYOUT_ACCEPTED")
				}
			}
		})
	}
}

func TestRetainedOriginal83ShiftedFrames(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original29_30", "shifted29_30", "extra_component"} {
		t.Run(mode, func(t *testing.T) {
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				d := retainedDescriptorInput("local")
				d.LayoutDigest = retainedLocalLayout83Digest()
				d.ComponentInventories = nil
				layout := aggregateLocalTables83()
				for _, table := range layout {
					sum := sha256.New()
					prefix, _ := automationCutFrame("section/v1", []byte(table.descriptor().name))
					sum.Write(prefix)
					d.ComponentInventories = append(d.ComponentInventories, automationCutInventory{table.descriptor().name, 1, 0, 0, hex.EncodeToString(sum.Sum(nil))})
				}
				a, err := retainedAddress(strings.Repeat("c", 64), 2, d.Source, d.OriginalIdentity, retainedLocalStream)
				if err != nil {
					return err
				}
				for _, section := range []int{29, 30} {
					table := layout[section]
					var values []any
					for _, kind := range table.shape {
						if kind == 'i' {
							values = append(values, int64(1))
						} else {
							values = append(values, "original")
						}
					}
					raw, err := encodeAggregateLocalRecord(table.descriptor().name, 1, Row{Columns: strings.Split(table.columns, ","), Values: values})
					if err != nil {
						return err
					}
					sum := sha256.New()
					prefix, _ := automationCutFrame("section/v1", []byte(table.descriptor().name))
					sum.Write(prefix)
					sum.Write(raw)
					d.ComponentInventories[section] = automationCutInventory{table.descriptor().name, 1, 1, int64(len(raw)), hex.EncodeToString(sum.Sum(nil))}
					destination := section
					if mode == "shifted29_30" {
						destination = 59 - section
					}
					if err = a.save(ctx, tx, destination, 1, raw); err != nil {
						return err
					}
				}
				if mode == "extra_component" {
					if err = a.save(ctx, tx, 31, 1, []byte("unexpected")); err != nil {
						return err
					}
				}
				visited := 0
				err = a.walk(ctx, tx, d, func(section int, n int64, raw []byte) error {
					if section != 29 && section != 30 {
						return fmt.Errorf("wrong old section %d", section)
					}
					visited++
					return nil
				})
				if mode == "original29_30" {
					if err != nil || visited != 2 {
						return fmt.Errorf("RETAINED83_ORIGINAL_FRAMES_REFUSED: %d %v", visited, err)
					}
				} else if err == nil {
					return fmt.Errorf("RETAINED83_SHIFTED_OR_EXTRA_FRAMES_ACCEPTED: %s", mode)
				}
				// Restore synthetic consumed-format rows for independent sibling cases.
				_, cleanup := tx.Exec(ctx, `DELETE FROM local_automation_local_rows WHERE local_id=?`, a.localID)
				return cleanup
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
