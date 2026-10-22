package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
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
	if len(old) != 31 || len(current) != 38 || old[29].table != "local_automation_lifetimes" || old[30].table != "local_automation_credential_issuance" || current[29].table != "local_automation_target_operations" || current[30].table != "local_automation_target_reservations" {
		t.Fatal("RETAINED83_SECTION_SHIFT")
	}
	if retainedLocalLayout83Digest() == retainedLocalLayoutDigest() {
		t.Fatal("RETAINED83_LAYOUT_RELABELED")
	}
	for _, which := range []string{"old83", "current86"} {
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

// These are consumed-format matrix controls, not claims of historical export
// or authenticated aggregate acceptance. The genuine85 companion is separate.
func TestRetainedCompatibilityDescriptorAndFrameBounds(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	layouts := []struct {
		name, digest string
		tables       []aggregateLocalTable
		suffix       int
	}{
		{"archived31", "dad4d14693e2ba5b6637571a8a80f6ba3c37bf55094ff2be92dfae26bbb36b1a", aggregateLocalTables83(), 29},
		{"old33", "09e38c2616d9155ed46e134be62b051aaef50a549c538b11c644040f4e710fec", automationExecutionArchived85PrivateLayoutForTest(), 31},
		{"current37", "5bc44346e864a2ccfa79a754ad45a697f60e71952b6db325d4289b92674a92a3", automationExecutionCurrent86PrivateLayoutForTest(), 35},
		{"archived38", login88Layout, aggregateLocalTables88(), 36},
		{"current89", "82aab9aae0d6cd4aada95900cf66bb4564e48a8795486f43e9de7b8e0ac58494", aggregateLocalTables(), 36},
	}
	for _, layout := range layouts {
		t.Run(layout.name, func(t *testing.T) {
			admitted, dispatchErr := retainedLocalTablesForDigest(layout.digest)
			if dispatchErr != nil || !reflect.DeepEqual(admitted, layout.tables) {
				t.Fatal("production descriptor dispatch differs from frozen literal", dispatchErr)
			}
			if retainedLocalLayoutDigestFor(layout.tables) != layout.digest || len(layout.tables) != layout.suffix+2 || layout.tables[layout.suffix].table != "local_automation_lifetimes" || layout.tables[layout.suffix+1].table != "local_automation_credential_issuance" {
				t.Fatal("literal positional layout differs")
			}
			for _, mode := range []string{"original", "unknown", "changed-table", "changed-columns", "changed-key", "changed-shape", "mixed-layout", "truncated-inventory", "extra-inventory", "swapped-inventory", "swapped-frames", "truncated-frame", "extra-component", "malformed-frame", "oversized-frame"} {
				t.Run(mode, func(t *testing.T) {
					sqltx, err := c.db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer sqltx.Rollback()
					tx := &LocalTx{tx: sqltx}
					descriptor := retainedDescriptorInput("local")
					descriptor.LayoutDigest = layout.digest
					descriptor.ComponentInventories = nil
					for _, table := range layout.tables {
						sum := sha256.New()
						prefix, _ := automationCutFrame("section/v1", []byte(table.descriptor().name))
						sum.Write(prefix)
						descriptor.ComponentInventories = append(descriptor.ComponentInventories, automationCutInventory{table.descriptor().name, 1, 0, 0, hex.EncodeToString(sum.Sum(nil))})
					}
					address, err := retainedAddress(strings.Repeat("d", 64), 1, descriptor.Source, descriptor.OriginalIdentity, retainedLocalStream)
					if err != nil {
						t.Fatal(err)
					}
					for _, section := range []int{layout.suffix, layout.suffix + 1} {
						table := layout.tables[section]
						values := []any{}
						for _, kind := range table.shape {
							if kind == 'i' {
								values = append(values, int64(1))
							} else {
								values = append(values, "original")
							}
						}
						body, err := encodeAggregateLocalRecord(table.descriptor().name, 1, Row{Columns: strings.Split(table.columns, ","), Values: values})
						if err != nil {
							t.Fatal(err)
						}
						destination := section
						if mode == "swapped-frames" {
							destination = 2*layout.suffix + 1 - section
						}
						if mode == "malformed-frame" && section == layout.suffix {
							body = []byte("not-a-canonical-frame")
						}
						sum := sha256.New()
						prefix, _ := automationCutFrame("section/v1", []byte(table.descriptor().name))
						sum.Write(prefix)
						sum.Write(body)
						descriptor.ComponentInventories[section] = automationCutInventory{table.descriptor().name, 1, 1, int64(len(body)), hex.EncodeToString(sum.Sum(nil))}
						if mode == "truncated-frame" && section == layout.suffix {
							continue
						}
						if err = address.save(ctx, tx, destination, 1, body); err != nil {
							t.Fatal("bounded frame setup", err)
						}
					}
					if mode == "extra-component" {
						beforeSave := retainedCompatibilityRawRows(t, ctx, tx, "")
						err = address.save(ctx, tx, len(layout.tables), 1, []byte("extra"))
						if err != nil {
							if len(layout.tables) != len(aggregateLocalTables()) {
								t.Fatal("frame address ceiling differs from compiled current layout", err)
							}
							if !reflect.DeepEqual(beforeSave, retainedCompatibilityRawRows(t, ctx, tx, "")) {
								t.Fatal("storage ceiling refusal changed raw rows")
							}
							return
						}
					}
					if mode == "oversized-frame" {
						if _, err = tx.Exec(ctx, `UPDATE local_automation_local_rows SET record=? WHERE local_id=? AND section=? AND ordinal=1`, make([]byte, maxAggregateLocalRecordBytes+1), address.localID, layout.suffix); err != nil {
							t.Fatal(err)
						}
					}
					switch mode {
					case "unknown":
						descriptor.LayoutDigest = strings.Repeat("f", 64)
					case "changed-table", "changed-columns", "changed-key", "changed-shape":
						changed := append([]aggregateLocalTable(nil), layout.tables...)
						switch mode {
						case "changed-table":
							changed[layout.suffix].table += "_future"
						case "changed-columns":
							changed[layout.suffix].columns += ",future"
						case "changed-key":
							changed[layout.suffix].keys += "_future"
						case "changed-shape":
							changed[layout.suffix].shape += "t"
						}
						descriptor.LayoutDigest = retainedLocalLayoutDigestFor(changed)
					case "mixed-layout":
						if layout.name == "current37" {
							descriptor.LayoutDigest = layouts[1].digest
						} else {
							descriptor.LayoutDigest = layouts[2].digest
						}
					case "truncated-inventory":
						descriptor.ComponentInventories = descriptor.ComponentInventories[:len(descriptor.ComponentInventories)-1]
					case "extra-inventory":
						descriptor.ComponentInventories = append(descriptor.ComponentInventories, descriptor.ComponentInventories[0])
					case "swapped-inventory":
						descriptor.ComponentInventories[layout.suffix], descriptor.ComponentInventories[layout.suffix+1] = descriptor.ComponentInventories[layout.suffix+1], descriptor.ComponentInventories[layout.suffix]
					}
					directoryAddress, err := retainedAddress(strings.Repeat("d", 64), 0, descriptor.Source, strings.Repeat("a", 64), retainedMetadataStream)
					if err != nil {
						t.Fatal(err)
					}
					// Keep ordinals closed while exercising real directory.find and storage.walk.
					entry, _ := json.Marshal(retainedDirectoryEntry{1, descriptor})
					if err = directoryAddress.save(ctx, tx, 0, 1, entry); err != nil {
						t.Fatal(err)
					}
					hostile := retainedCompatibilityRawRows(t, ctx, tx, "")
					directory := retainedDirectoryReader{directoryAddress, 1}
					got, objectAddress, err := directory.find(ctx, tx, "local", descriptor.OriginalIdentity)
					if err == nil {
						visited := 0
						err = objectAddress.walk(ctx, tx, got, func(section int, n int64, body []byte) error { visited++; return nil })
						if mode == "original" && visited != 2 {
							t.Fatal("original suffix frames not visited", visited)
						}
					}
					if mode == "original" {
						if err != nil {
							t.Fatal("literal complete frames refused", err)
						}
					} else if err == nil {
						t.Fatal("invalid directory/layout/frame accepted", mode)
					}
					if !reflect.DeepEqual(hostile, retainedCompatibilityRawRows(t, ctx, tx, "")) {
						t.Fatal("directory/storage traversal changed hostile original or ACTIVE before rollback", mode)
					}
					if err = sqltx.Rollback(); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
