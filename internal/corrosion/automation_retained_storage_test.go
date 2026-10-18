package corrosion

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRetainedFrameStorageBoundAndIsolation(t *testing.T) {
	_, v, _, _ := threeVoters(t)
	ctx := context.Background()
	active := receiverActive(t, v.c)
	d := strings.Repeat("a", 64)
	local, err := retainedAddress(d, 1, "a", strings.Repeat("b", 64), retainedLocalStream)
	if err != nil {
		t.Fatalf("closed local snapshot address unavailable: %v", err)
	}
	source, err := retainedAddress(d, 2, "a", strings.Repeat("b", 64), retainedSourceStream)
	if err != nil {
		t.Fatal(err)
	}
	if local.namespace == source.namespace || !receiverDigest(local.localID) || source.localID != "" || len(local.namespace) > 96 {
		t.Fatal("closed storage/authentication identities overlap")
	}
	tx, err := v.c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	store := &LocalTx{tx: tx}
	// Raw storage bound probe only; semantic record codecs run independently.
	// A local frame may exceed the ordinary record bound without widening it.
	full := bytes.Repeat([]byte("x"), maxAggregateLocalRecordBytes)
	if err = local.save(ctx, store, 0, 1, full); err != nil {
		t.Fatalf("native maximum local frame refused: %v", err)
	}
	if err = local.save(ctx, store, 0, 1, full); err != nil {
		t.Fatal("exact local retry", err)
	}
	got, err := local.read(ctx, store, 0, 1)
	if err != nil || !bytes.Equal(full, got) {
		t.Fatal("bounded local original changed", err)
	}
	if err = source.save(ctx, store, 3, 1, full); err == nil {
		t.Fatal("ordinary record bound widened by local snapshot")
	}
	if err = local.save(ctx, store, 0, 1, []byte("changed")); err == nil {
		t.Fatal("contradictory local retry overwrote original")
	}
	if err = local.save(ctx, store, 0, 2, append(full, 'x')); err == nil {
		t.Fatal("over-bound local frame accepted")
	}
	if err = source.save(ctx, store, 3, 1, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err = source.save(ctx, store, 3, 1, []byte("original")); err != nil {
		t.Fatal("exact ordinary-address retry", err)
	}
	if err = source.save(ctx, store, 3, 1, []byte("changed")); err == nil {
		t.Fatal("contradictory source retry overwrote original")
	}
	rows, err := store.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_records WHERE attempt=?`, local.namespace)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != 0 {
		t.Fatal("large local snapshot leaked into ordinary receiver records", err)
	}
	if _, err = tx.Exec(`UPDATE local_automation_local_rows SET record=? WHERE local_id=?`, strings.Repeat("x", maxAggregateLocalRecordBytes+1), local.localID); err != nil {
		t.Fatal(err)
	}
	if _, err = local.read(ctx, store, 0, 1); err == nil {
		t.Fatal("oversized wrong-type stored local body accepted")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if receiverActive(t, v.c) != active {
		t.Fatal("storage adapter modified ACTIVE state")
	}
}
