package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Review NB-4: one disk in a pool whose header cannot be read holds every
// replica removal there — the guard stays strict — and says so: the host
// raises replica_removal_held for the pool, naming the disk and the replicas
// it keeps, and the replica's VM gets an event, once per hour while it lasts.
// Once the disk reads again the next prune removes what it held and the
// condition is resolved.
//
// Mutation "log only" (held raises nothing) — red on the raise. Mutation
// "never cleared" (cleared does nothing) — red on the resolve. Mutation "not
// rate-limited" (notify on every hold) — red on the event count.
func TestReplicaHold_AnUnreadableDiskHoldingAPoolsRemovalsIsNamedUntilItReads(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "dr", Driver: "local", Target: poolDir})
	var reps []string
	for _, ago := range []time.Duration{30 * time.Minute, 20 * time.Minute, 10 * time.Minute} {
		reps = append(reps, filepath.Join(replicaOwnerDir(poolDir, "", "db"),
			seedReplica(t, poolDir, "", "db", "root", stamp(ago), "raw", 1<<10)))
	}
	// Another VM's disk in the pool, whose qcow2 header is cut short.
	other := filepath.Join(poolDir, "other-root.qcow2")
	if err := os.WriteFile(other, []byte("QFI\xfb"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := `{"name":"other"}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "other", HostName: s.hostName, State: "running", Spec: spec},
		nil, []corrosion.DiskRecord{{VMName: "other", DiskName: "root", HostName: s.hostName, Path: other, StorageType: "local", StorageVolume: "dr"}}); err != nil {
		t.Fatal(err)
	}
	cond := func() corrosion.HealthCondition {
		t.Helper()
		row, found, err := corrosion.GetHealthCondition(ctx, s.db, replicaRemovalEvaluator, condReplicaRemovalHeld, "host", s.hostName+"/dr")
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			return corrosion.HealthCondition{}
		}
		return row
	}
	events := func() (n int, detail string) {
		evs, err := corrosion.ListVMEvents(ctx, s.db, "db", 100, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			if e.Type == vmEventReplicaRemovalHeld {
				n, detail = n+1, e.Detail
			}
		}
		return n, detail
	}

	for pass := 1; pass <= 2; pass++ {
		if n, err := s.pruneRecordedReplicas(ctx, "dr", "", "db", "root", "db/test", 1); err != nil || n != 0 {
			t.Fatalf("pass %d: prune with an unreadable disk in the pool removed %d (err %v), want 0", pass, n, err)
		}
	}
	row := cond()
	if row.Code == "" || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no live %s for pool dr after two held prunes: %+v", condReplicaRemovalHeld, row)
	}
	for _, want := range []string{other, filepath.Base(reps[0]), `"pool":"dr"`} {
		if !strings.Contains(row.Evidence, want) {
			t.Errorf("evidence = %s, want it to name %q", row.Evidence, want)
		}
	}
	if n, detail := events(); n != 1 || !strings.Contains(detail, other) || !strings.Contains(detail, condReplicaRemovalHeld) {
		t.Errorf("db has %d %s event(s), detail %q; want one naming %s and the condition", n, vmEventReplicaRemovalHeld, detail, other)
	}
	// A pool content delete it holds raises nothing new, and is refused.
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{
		PoolName: "dr", Filename: filepath.Base(reps[0]), ReplicaVm: "db"}); err == nil || !lexists(reps[0]) {
		t.Errorf("delete with an unreadable disk in the pool = %v, want refused and kept", err)
	}

	// The disk reads again: the next prune removes what was held and the
	// condition is resolved.
	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := s.pruneRecordedReplicas(ctx, "dr", "", "db", "root", "db/test", 1); err != nil || n != 2 {
		t.Errorf("prune once the disk reads removed %d (err %v), want 2", n, err)
	}
	if row := cond(); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("%s after a prune that read every disk = %+v, want resolved", condReplicaRemovalHeld, row)
	}
}
