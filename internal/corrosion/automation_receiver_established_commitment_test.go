package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReceiverEstablishedInventoryAuthentication(t *testing.T) {
	for _, mode := range []string{"signature", "noncanonical", "empty", "type", "oversize", "count", "context"} {
		t.Run(mode, func(t *testing.T) {
			f := currentProofFixture(t)
			ctx := context.Background()
			rows, err := f.local.c.Query(ctx, `SELECT established_inventory AS inventory FROM local_automation_receiver_current`)
			if err != nil || len(rows) != 1 {
				t.Fatal(err)
			}
			raw := rows[0].Bytes("inventory")
			var signed receiverInventoryArtifact
			if err = json.Unmarshal(raw, &signed); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "signature":
				signed.Signature[0] ^= 1
				raw, err = json.Marshal(signed)
			case "noncanonical":
				raw = append(raw, ' ')
			case "empty":
				raw = []byte{}
			case "count", "context":
				var m receiverInventoryManifest
				if err = json.Unmarshal(signed.Manifest, &m); err != nil {
					t.Fatal(err)
				}
				if mode == "count" {
					m.Inventory.Count++
				} else {
					m.Host = "peer"
				}
				signed.Manifest, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = json.Marshal(signed)
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "type":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_receiver_current SET established_inventory=CAST(established_inventory AS TEXT)`)
			case "oversize":
				_, err = f.local.c.db.Exec(`UPDATE local_automation_receiver_current SET established_inventory=zeroblob(?)`, maxReceiverInventoryBytes+1)
			default:
				_, err = f.local.c.db.Exec(`UPDATE local_automation_receiver_current SET established_inventory=?`, raw)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := receiverAllStored(t, f.local.c)
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			if a, e := f.receiver.Begin(ctx, f.attempt.request, nil); e == nil || a != nil {
				t.Fatal("malformed inventory accepted normal start", mode, e)
			}
			if e := f.receiver.Reestablish(ctx, f.attempt.request); e == nil {
				t.Fatal("malformed inventory cleared by repair", mode)
			}
			if before != receiverAllStored(t, f.local.c) || active != receiverActive(t, f.local.c) || spool != receiverStored(t, f.local.c) {
				t.Fatal("inventory refusal changed retained state")
			}
		})
	}
}
func TestReceiverEstablishedInventoryDuplicateAndStream(t *testing.T) {
	f := currentProofFixture(t)
	ctx := context.Background()
	before, err := f.local.c.Query(ctx, `SELECT established_inventory AS inventory FROM local_automation_receiver_current`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.receiver.Begin(ctx, f.attempt.request, nil); err != nil {
		t.Fatal(err)
	}
	after, err := f.local.c.Query(ctx, `SELECT established_inventory AS inventory FROM local_automation_receiver_current`)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before[0].Bytes("inventory"), after[0].Bytes("inventory")) {
		t.Fatal("duplicate known validation rewrote authenticated inventory")
	}
	current, err := f.receiver.inventoryRoot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.local.c.Query(ctx, `SELECT attempt,digest FROM local_automation_receiver_validations ORDER BY attempt,digest`)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	key := receiverValidationKey{rows[0].String("attempt"), rows[0].String("digest")}
	duplicate, err := f.receiver.inventoryRoot(ctx, &key)
	if err != nil || duplicate != current {
		t.Fatal("exact union duplicate changed root", err)
	}
	if err = f.local.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		actual, e := receiverInventoryRootTx(ctx, tx)
		if e == nil && actual != current {
			t.Fatal("FULL root differs")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	stream := newReceiverInventoryStream(nil)
	if err = stream.add(key); err != nil {
		t.Fatal(err)
	}
	if err = stream.add(key); err == nil {
		t.Fatal("duplicate streamed key accepted")
	}
	stream = newReceiverInventoryStream(nil)
	if err = stream.add(receiverValidationKey{key.attempt, "not-a-digest"}); err == nil {
		t.Fatal("malformed streamed key accepted")
	}
	extra := receiverValidationKey{strings.Repeat("f", 64), strings.Repeat("e", 64)}
	expanded, err := f.receiver.inventoryRoot(ctx, &extra)
	if err != nil || expanded.Count != current.Count+1 || expanded.Digest == current.Digest {
		t.Fatal("streamed count/end omitted extra key", err)
	}
	empty, err := newReceiverInventoryStream(nil).finish()
	if err != nil || empty.Count != 0 || empty.Digest == current.Digest {
		t.Fatal("empty/count/end omitted", err)
	}
}
func TestReceiverEstablishedInventoryActualLegacyUpgrade(t *testing.T) {
	f := currentProofFixture(t)
	ctx := context.Background()
	old, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP TABLE local_automation_receiver_established`, `ALTER TABLE local_automation_receiver_current DROP COLUMN established_inventory`, `DELETE FROM applied_migrations WHERE id='t_local_automation_receiver_established' OR id LIKE '%local_automation_receiver_current_established_inventory'`, `UPDATE schema_state SET version=77`} {
		if _, err = f.local.c.db.Exec(q); err != nil {
			t.Fatal("actual legacy shape", err)
		}
	}
	if err = InitSchema(ctx, f.local.c); err != nil {
		t.Fatal("actual prior-table ALTER upgrade", err)
	}
	if _, err = f.receiver.Begin(ctx, f.attempt.request, nil); err == nil {
		t.Fatal("legacy empty commitment silently accepted")
	}
	if err = f.receiver.Reestablish(ctx, f.attempt.request); err != nil {
		t.Fatal("genuine legacy explicit current-owner repair", err)
	}
	if err = f.receiver.consumeCurrent(ctx, old); err == nil {
		t.Fatal("old pre-upgrade proof revived")
	}
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.receiver.consumeCurrent(ctx, p); err != nil {
		t.Fatal(err)
	}
}
