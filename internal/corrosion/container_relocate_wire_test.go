package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// shipWAL applies every entry src logged after seq `after` to dst, as a push
// would, and returns how many entries that was.
func shipWAL(t *testing.T, src, dst *Client, after int64) (int, error) {
	t.Helper()
	var entries = walEntries(t, src, "relocating-node")
	var tail = entries[:0:0]
	for _, e := range entries {
		if e.Seq > after {
			tail = append(tail, e)
		}
	}
	_, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), tail)
	return len(tail), err
}

func lastWALSeq(t *testing.T, c *Client) int64 {
	t.Helper()
	entries := walEntries(t, c, "")
	if len(entries) == 0 {
		return 0
	}
	return entries[len(entries)-1].Seq
}

// A relocation is one local transaction, but what it logs must be entries a
// receiver accepts. It used to log one entry with the source's guarded
// tombstone in the middle and the unguarded target row after it; every
// receiver refused that ("guarded workload transition/delete must be the unique
// final statement"), and because the refusal back-pressures, the relocating
// node's whole replication stream stopped there. Both target shapes are
// covered: a pre-epoch source takes the retained upsert, a lifecycle-bearing
// one the guarded pending insert.
func TestRelocateContainerWithToken_EntriesApplyOnAPeer(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lifecycle bool
	}{{"pre-epoch", false}, {"lifecycle", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			src, dst := newTestDB(t), newTestDB(t)
			seedRelocatableContainer(t, src, "host-a", "web", tc.lifecycle)
			if _, err := shipWAL(t, src, dst, 0); err != nil {
				t.Fatalf("ship seed: %v", err)
			}
			if tc.lifecycle {
				// seedRelocatableContainer sets these unlogged; mirror them.
				if _, err := dst.db.Exec(`UPDATE containers SET owner_epoch = 3, spec_generation = 2
					WHERE host_name = 'host-a' AND name = 'web'`); err != nil {
					t.Fatal(err)
				}
			}
			before := lastWALSeq(t, src)

			if err := RelocateContainerWithToken(ctx, src, "host-a", "web", "host-b", "tok-wire"); err != nil {
				t.Fatalf("relocate: %v", err)
			}
			n, err := shipWAL(t, src, dst, before)
			if err != nil {
				t.Fatalf("a peer refused the relocation's entries (%d shipped): %v", n, err)
			}
			if n != 2 {
				t.Errorf("relocation logged %d entries, want 2: the guarded tombstone alone, then the target", n)
			}
			if s, _ := GetContainer(ctx, dst, "host-a", "web"); s != nil {
				t.Errorf("peer still holds the source live: %+v", s)
			}
			d, err := GetContainer(ctx, dst, "host-b", "web")
			if err != nil || d == nil {
				t.Fatalf("peer has no target row: err=%v", err)
			}
			if d.RelocateToken != "tok-wire" || d.StateDetail != ContainerRelocateRecreateDetail {
				t.Errorf("peer target = token %q detail %q", d.RelocateToken, d.StateDetail)
			}
			if tc.lifecycle && d.OwnerEpoch != 3 {
				t.Errorf("peer target owner_epoch = %d, want the source's 3", d.OwnerEpoch)
			}
		})
	}
}

// legacyRelocationStmts builds the relocation exactly as the single-entry
// builder (e062efe1 until the split) logged it: guarded cleanup, guarded
// tombstone, then the unguarded target row, all in one entry.
func legacyRelocationStmts(t *testing.T, c *Client, host, name, toHost string) ([]Statement, *MutationGuard) {
	t.Helper()
	old, err := GetContainer(context.Background(), c, host, name)
	if err != nil || old == nil {
		t.Fatalf("read source: %+v %v", old, err)
	}
	guard, err := containerDeleteMutationGuard(*old)
	if err != nil {
		t.Fatal(err)
	}
	rec := *old
	rec.HostName, rec.State, rec.StateDetail, rec.CreatedAt = toHost, "pending", ContainerRelocateRecreateDetail, ""
	rec.RelocateToken = "tok-legacy"
	var target Statement
	if old.OwnerEpoch == 0 && old.SpecGeneration == 0 && old.ActiveOperationID == "" {
		if target, err = upsertContainerStmt(c, rec, firewallIDOf(TagMemberCT, old.CreateSpec)); err != nil {
			t.Fatal(err)
		}
	} else {
		target = Statement{SQL: containerRelocatePendingInsertSQL, Params: []interface{}{
			rec.HostName, rec.Name, rec.Image, rec.CPULimit, rec.MemMiB, "",
			rec.RestartPolicy, rec.StateDetail, rec.Project, boolToInt(rec.IsTemplate),
			rec.OnHostFailure, rec.CreateSpec, rec.RelocateToken,
			old.OwnerEpoch, old.SpecGeneration, old.ActiveOperationID,
			nowRFC3339(), c.NowTS(),
		}}
	}
	now, wall := c.NowTS(), nowRFC3339()
	return []Statement{
		{SQL: containerCreateCleanupSQL, Params: []interface{}{wall, now, old.HostName, old.Name}, Guard: guard},
		{SQL: containerDeleteSQL, Params: []interface{}{
			wall, now, old.HostName, old.Name, old.OwnerEpoch, old.SpecGeneration,
		}, Guard: guard},
		target,
	}, guard
}

// The local write path refuses an entry a receiver would refuse, BEFORE it
// commits. This is the old relocation's exact batch: committed, it stalls the
// node's stream for every peer until it ages out of the log; refused, it is an
// error at the call site that wrote it.
func TestExecuteBatchGuarded_RefusesAnEntryPeersWouldReject(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	seedRelocatableContainer(t, c, "host-a", "web", true)
	stmts, guard := legacyRelocationStmts(t, c, "host-a", "web", "host-b")
	logged := mutationLogCount(t, c)
	_, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		return c.mutationGuardMatches(ctx, tx, guard)
	}, stmts)
	if !errors.Is(err, ErrInvalidStmt) {
		t.Fatalf("err = %v, want the receiver's ErrInvalidStmt refusal at write time", err)
	}
	if got := mutationLogCount(t, c); got != logged {
		t.Errorf("mutation_log grew by %d: the refused entry reached the log", got-logged)
	}
	if s, _ := GetContainer(ctx, c, "host-a", "web"); s == nil {
		t.Error("the refused write still tombstoned the source locally")
	}
	if d, _ := GetContainer(ctx, c, "host-b", "web"); d != nil {
		t.Errorf("the refused write still created the target locally: %+v", d)
	}
}

// The single-entry relocation shape (e062efe1 until the split, never in a
// release) is refused on receipt like any other malformed guarded entry: the
// receiver applies nothing from it.
func TestReplicator_RefusesSingleEntryRelocation(t *testing.T) {
	ctx := context.Background()
	src, dst := newTestDB(t), newTestDB(t)
	seedRelocatableContainer(t, src, "host-a", "web", true)
	if _, err := shipWAL(t, src, dst, 0); err != nil {
		t.Fatalf("ship seed: %v", err)
	}
	stmts, _ := legacyRelocationStmts(t, src, "host-a", "web", "host-b")
	b, err := json.Marshal(stmts)
	if err != nil {
		t.Fatal(err)
	}
	entry := &pb.MutationEntry{Seq: 1, Hlc: src.Clock().Now().String(), Origin: "old-build", Stmts: string(b)}
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx,
		[]*pb.MutationEntry{entry}); !errors.Is(err, ErrInvalidStmt) {
		t.Fatalf("err = %v, want the entry refused", err)
	}
	if s, _ := GetContainer(ctx, dst, "host-a", "web"); s == nil {
		t.Error("the refused entry tombstoned the source")
	}
	if d, _ := GetContainer(ctx, dst, "host-b", "web"); d != nil {
		t.Errorf("the refused entry created the target: %+v", d)
	}
}
