package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
	"testing"
)

func TestRetainedLocalFrameInventoryManyRows(t *testing.T) {
	_, v, _, _ := threeVoters(t)
	ctx := context.Background()
	active := receiverActive(t, v.c)
	tx, err := v.c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	local := &LocalTx{tx: tx}
	d := retainedDescriptorInput("local")
	d.Source = v.name
	a, err := retainedAddress(strings.Repeat("a", 64), 1, v.name, d.OriginalIdentity, retainedLocalStream)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make([]hash.Hash, len(d.ComponentInventories))
	for i, inv := range d.ComponentInventories {
		h := sha256.New()
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		h.Write(prefix)
		hashes[i] = h
	}
	// 130 independently framed rows plus a near-native body exercise real SQL
	// keysets. These are structural snapshots, not semantic/adopted evidence.
	section := 2
	layout := aggregateLocalTables()[section]
	for ordinal := int64(1); ordinal <= 130; ordinal++ {
		value := "value"
		if ordinal == 65 {
			value = strings.Repeat("x", maxAutomationCutRecordBytes-1024)
		}
		row := Row{Columns: aggregateLocalColumns(layout.columns), Values: []any{ordinal, strings.Repeat("a", 64), value, "certificate", "receipt", int64(1)}}
		raw, err := encodeAggregateLocalRecord(layout.descriptor().name, ordinal, row)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.save(ctx, local, section, ordinal, raw); err != nil {
			t.Fatal(err)
		}
		hashes[section].Write(raw)
		d.ComponentInventories[section].Records++
		d.ComponentInventories[section].Bytes += int64(len(raw))
	}
	for i, h := range hashes {
		d.ComponentInventories[i].Digest = hex.EncodeToString(h.Sum(nil))
	}
	seen := int64(0)
	if err = a.walk(ctx, local, d, func(s int, n int64, raw []byte) error {
		if s != section || n != seen+1 {
			t.Fatal("walker reordered original body")
		}
		seen++
		return nil
	}); err != nil {
		t.Fatalf("complete keyset local frame walk refused: %v", err)
	}
	if seen != 130 {
		t.Fatalf("walked %d originals", seen)
	}
	for _, mode := range []string{"missing", "extra-section", "fractional-ordinal", "blob-ordinal", "wrong-body-type", "corrupt-body", "wrong-empty-digest"} {
		t.Run(mode, func(t *testing.T) {
			var err error
			if _, err := tx.Exec(`SAVEPOINT retained_walk_negative`); err != nil {
				t.Fatal(err)
			}
			defer tx.Exec(`ROLLBACK TO retained_walk_negative`)
			copy := d
			copy.ComponentInventories = append([]automationCutInventory(nil), d.ComponentInventories...)
			switch mode {
			case "missing":
				_, err = tx.Exec(`DELETE FROM local_automation_local_rows WHERE local_id=? AND section=? AND ordinal=17`, a.localID, section)
			case "extra-section":
				_, err = tx.Exec(`INSERT INTO local_automation_local_rows(local_id,section,ordinal,record) VALUES(?,?,1,?)`, a.localID, len(aggregateLocalTables()), []byte("x"))
			case "fractional-ordinal":
				_, err = tx.Exec(`UPDATE local_automation_local_rows SET ordinal=17.5 WHERE local_id=? AND section=? AND ordinal=17`, a.localID, section)
			case "blob-ordinal":
				_, err = tx.Exec(`UPDATE local_automation_local_rows SET ordinal=x'61' WHERE local_id=? AND section=? AND ordinal=17`, a.localID, section)
			case "wrong-body-type":
				_, err = tx.Exec(`UPDATE local_automation_local_rows SET record='text' WHERE local_id=? AND section=? AND ordinal=17`, a.localID, section)
			case "corrupt-body":
				_, err = tx.Exec(`UPDATE local_automation_local_rows SET record=x'6162' WHERE local_id=? AND section=? AND ordinal=17`, a.localID, section)
			case "wrong-empty-digest":
				copy.ComponentInventories[0].Digest = strings.Repeat("b", 64)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = a.walk(ctx, local, copy, nil); err == nil {
				t.Fatal("invalid full retained inventory accepted")
			}
		})
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, v.c) != active {
		t.Fatal("frame walker changed ACTIVE state")
	}
}
