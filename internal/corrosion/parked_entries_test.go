package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// parkTestClient is a schema'd client closed at test end.
func parkTestClient(t *testing.T) *Client {
	t.Helper()
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func snapEntry(t *testing.T, seq int64, origin, id, vm, name string) *pb.MutationEntry {
	t.Helper()
	hlcTS := fmt.Sprintf("%013d-0000-%s", 1700000000000+seq, origin)
	stmts := []Statement{{SQL: insertSnapshotSQL, Params: []interface{}{
		id, vm, origin, name, "ok", 1, "disk", "", 0, "2026-10-12T00:00:00Z", hlcTS,
	}}}
	b, err := json.Marshal(stmts)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.MutationEntry{Seq: seq, Hlc: hlcTS, Origin: origin, Stmts: string(b)}
}

// seedLiveSnapshot puts a live row under (vm, name) on c only, as a peer's
// independently created snapshot would be.
func seedLiveSnapshot(t *testing.T, c *Client, id, vm, name string) {
	t.Helper()
	if _, err := c.DB().Exec(`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at)
		VALUES (?, ?, 'here', ?, 'ok', '2026-01-01T00:00:00Z', '0000000000001-0000-here')`, id, vm, name); err != nil {
		t.Fatal(err)
	}
}

func uniqueConstraintErr(t *testing.T, c *Client) error {
	t.Helper()
	seedLiveSnapshot(t, c, "u1", "uvm", "u")
	_, err := c.DB().Exec(`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at)
		VALUES ('u2', 'uvm', 'here', 'u', 'ok', '', '')`)
	if err == nil {
		t.Fatal("expected a UNIQUE failure")
	}
	return err
}

// Only an unguarded LWW row write to an anti-entropy table, refused by a
// constraint, may be held. Every other failure keeps back-pressuring.
func TestEntryParkable_Boundaries(t *testing.T) {
	c := parkTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	uniq := uniqueConstraintErr(t, c)
	ins := Statement{SQL: insertSnapshotSQL, Params: make([]interface{}, 11)}

	if table, _, ok := r.entryParkable([]Statement{ins}, ins, uniq); !ok || table != "snapshots" {
		t.Fatalf("a snapshot insert refused by UNIQUE is not holdable: %q %v", table, ok)
	}
	if _, _, ok := r.entryParkable([]Statement{ins}, ins, errors.New("database is locked")); ok {
		t.Fatal("a non-constraint failure was holdable")
	}
	if _, _, ok := r.entryParkable([]Statement{ins}, ins, fmt.Errorf("x: %w", errors.New("no such column: foo"))); ok {
		t.Fatal("a schema-missing failure was holdable")
	}
	guarded := ins
	guarded.Guard = &MutationGuard{Protocol: workloadCreateGuardV1}
	if _, _, ok := r.entryParkable([]Statement{guarded}, guarded, uniq); ok {
		t.Fatal("a guarded entry was holdable")
	}
	users := Statement{SQL: usersInsertSQL}
	if _, _, ok := r.entryParkable([]Statement{users}, users, uniq); ok {
		t.Fatal("a users write (absorbs and the re-mint floor) was holdable")
	}
	for _, s := range []Statement{users, {SQL: insertFenceLogSQL}} {
		sh, _, err := parseResolved(s.SQL)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := LedgerLookup(stmtFingerprint(sh)); !ok {
			t.Fatalf("test statement is not a registered shape, so the refusal below is vacuous: %s", s.SQL)
		}
	}
	// One non-LWW statement anywhere in the entry keeps the whole entry
	// back-pressuring: it would be applied later, out of its order.
	appendOnly := Statement{SQL: insertFenceLogSQL}
	if _, _, ok := r.entryParkable([]Statement{ins, appendOnly}, ins, uniq); ok {
		t.Fatal("an entry carrying an append-only statement was holdable")
	}
}

// A held entry is recorded seen (a re-delivery is not held twice), relayed by
// a relay like any applied entry, and the entries after it apply.
func TestApplyRemoteMutations_HeldEntryIsSeenAndRelayed(t *testing.T) {
	c := parkTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	seedLiveSnapshot(t, c, "mine", "vm", "s1")

	e1 := snapEntry(t, 1, "peer", "theirs", "vm", "s1") // refused: UNIQUE(vm_name, name)
	e2 := snapEntry(t, 2, "peer", "other", "vm", "s2")
	seq, err := r.ApplyRemoteMutationsFrom(ctx, []*pb.MutationEntry{e1, e2}, true)
	if err != nil || seq != 2 {
		t.Fatalf("apply = (%d, %v), want (2, nil)", seq, err)
	}
	if rows, _ := c.Query(ctx, `SELECT id FROM snapshots WHERE vm_name = 'vm' AND name = 's2'`); len(rows) != 1 {
		t.Fatal("the entry after the held one did not apply")
	}
	if rows, _ := c.Query(ctx, `SELECT id FROM snapshots WHERE vm_name = 'vm' AND name = 's1'`); len(rows) != 1 || rows[0].String("id") != "mine" {
		t.Fatalf("the local row the held entry conflicts with changed: %v", rows)
	}
	if rows, _ := c.Query(ctx, `SELECT hlc FROM mutation_seen WHERE origin = 'peer'`); len(rows) != 2 {
		t.Fatalf("mutation_seen rows = %d, want 2 (held entries are seen)", len(rows))
	}
	if rows, _ := c.Query(ctx, `SELECT hlc FROM mutation_log WHERE origin = 'peer' AND hlc = ?`, e1.Hlc); len(rows) != 1 {
		t.Fatal("a relay did not forward the held entry")
	}
	if p := r.ParkedEntries(); len(p) != 1 || p[0].Seq != 1 || p[0].Origin != "peer" {
		t.Fatalf("held = %+v", p)
	}
	// Re-delivery: seen, so neither re-applied nor held twice.
	if _, err := r.ApplyRemoteMutationsFrom(ctx, []*pb.MutationEntry{e1, e2}, false); err != nil {
		t.Fatal(err)
	}
	if p := r.ParkedEntries(); len(p) != 1 {
		t.Fatalf("a re-delivered held entry was held again: %+v", p)
	}
	if got := r.ParkedCounts()["peer"]; got != 1 {
		t.Fatalf("ParkedCounts[peer] = %d, want 1", got)
	}
}

// The hold is bounded. Past it a refusal back-pressures as before: nothing is
// acknowledged and nothing is lost.
func TestApplyRemoteMutations_HoldIsBoundedThenBackpressures(t *testing.T) {
	old := parkedEntriesMax
	parkedEntriesMax = 1
	t.Cleanup(func() { parkedEntriesMax = old })
	c := parkTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	seedLiveSnapshot(t, c, "m1", "vm", "a")
	seedLiveSnapshot(t, c, "m2", "vm", "b")

	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{snapEntry(t, 1, "peer", "t1", "vm", "a")}); err != nil {
		t.Fatalf("first refusal was not held: %v", err)
	}
	e2, e3 := snapEntry(t, 2, "peer", "t2", "vm", "b"), snapEntry(t, 3, "peer", "t3", "vm", "c")
	seq, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{e2, e3})
	if err == nil || seq != 0 {
		t.Fatalf("a refusal past the bound = (%d, %v), want back-pressure", seq, err)
	}
	if rows, _ := c.Query(ctx, `SELECT hlc FROM mutation_seen WHERE hlc IN (?, ?)`, e2.Hlc, e3.Hlc); len(rows) != 0 {
		t.Fatal("a back-pressured batch was recorded seen")
	}
	if rows, _ := c.Query(ctx, `SELECT id FROM snapshots WHERE name = 'c'`); len(rows) != 0 {
		t.Fatal("a back-pressured batch partly applied")
	}
}
