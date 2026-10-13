package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A start the walk read in starting, and an operator cancelled since
// (`lv stop --force` wrote stopped/operator-stop), is not made.
//
// Mutation: drop the cancelled-start check in startPendingVM — the VM is
// defined and started: red.
func TestStartPendingVM_ACancelledStartIsNotMade(t *testing.T) {
	for _, state := range []string{"pending", "starting"} {
		db := testReconcilerDB(t)
		ctx := context.Background()
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: state}, nil, nil); err != nil {
			t.Fatal(err)
		}
		walkRead, _ := corrosion.GetVM(ctx, db, "vm1")
		if err := corrosion.UpdateVMStateStrict(ctx, db, "vm1", "stopped", "operator-stop"); err != nil {
			t.Fatal(err)
		}
		fake := libvirtfake.New()
		r := NewReconciler("node-a", t.TempDir(), db, fake)
		r.SetGate(fakeGate{exec: GateResult{OK: true}})
		r.startPendingVM(ctx, *walkRead)
		if startedOrDefined(fake, "vm1") {
			t.Fatalf("%s: a start cancelled after the walk read it was made", state)
		}
	}
}

// vm_start_cancelled holds the VM's copies until it runs on its host, and
// clears then; a VM still stopped keeps it.
//
// Mutations: resolve regardless of the VM's state — cleared while stopped:
// red. Never resolve — still open once it runs: red.
func TestTendStrandedDisks_ClearsACancelledStartOnceTheVMRuns(t *testing.T) {
	db, fake, _, dataDir, _ := strandedFixture(t)
	ctx := context.Background()
	if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-a', state = 'stopped', state_detail = 'operator-stop', updated_at = ? WHERE name = 'web'`, db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordStartCancelled(ctx, db, "node-a", "web", "starting", time.Now()); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler("node-a", dataDir, db, fake)
	open := func() bool {
		row, ok, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMStartCancelled, "vm", "web@node-a")
		if err != nil || !ok {
			t.Fatalf("read vm_start_cancelled: %v %v", ok, err)
		}
		return row.Lifecycle != corrosion.ConditionResolved
	}
	r.tendStrandedDisks(ctx)
	if !open() {
		t.Fatal("cleared while the VM is still stopped")
	}
	if err := corrosion.UpdateVMStateStrict(ctx, db, "web", "running", ""); err != nil {
		t.Fatal(err)
	}
	fake.SetState("web", libvirtfake.StateRunning)
	r.tendStrandedDisks(ctx)
	if open() {
		t.Fatal("still open once the VM runs on its host")
	}
}
