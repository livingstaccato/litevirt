package health

import (
	"context"
	"os"
	"path/filepath"
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
	if _, err := RecordStartCancelled(ctx, db, "node-a", "web", "starting", false, time.Now()); err != nil {
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

// Review I-1: a cancelled proof-less transfer, made again by `lv start`
// (re-armed to "starting"), is still that transfer: the old copy at the disk
// path is set aside, as the cancelled start would have, although nothing in
// memory (deferredTransfers) remembers it after a daemon restart.
//
// Mutation: drop cancelledTransfer from startPendingVM's transfer test — the
// re-armed start is a local start, the old copy stays the disk: red.
func TestStartPendingVM_ACancelledTransferMadeAgainSetsTheOldCopyAside(t *testing.T) {
	db, fake, r, path := supersededFixture(t, "starting")
	ctx := context.Background()
	if _, err := RecordStartCancelled(ctx, db, "node-a", "vm1", "pending", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)
	if !startedOrDefined(fake, "vm1") {
		t.Fatal("vm1 was not started")
	}
	if aside, _ := filepath.Glob(path + ".superseded-*"); len(aside) != 1 {
		t.Fatalf("set-aside copies = %v, want the old copy the transfer found", aside)
	}
}

// A cancel of a start cancelled before keeps the transfer it recorded.
func TestRecordStartCancelled_KeepsATransfer(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if _, err := RecordStartCancelled(ctx, db, "node-a", "vm1", "pending", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordStartCancelled(ctx, db, "node-a", "vm1", "starting", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ev, err := StartCancelledOf(ctx, db, "vm1", "node-a"); err != nil || ev == nil || !ev.Transfer {
		t.Fatalf("record %+v (%v), want the transfer kept", ev, err)
	}
}

// Review m-1: the start lease can run out under a slow start, and a cancel
// (`lv stop --force`) then takes it and writes stopped/operator-stop while
// the start goes on. The start reads the row again before the define and
// again before the boot, and makes nothing: no define in the first case;
// in the second, what it defined is taken back and the domain never runs.
//
// Mutations: no check before the define — defined: red. No check before the
// boot — started: red.
func TestStartPendingVM_AStopDuringTheStartIsNotOverridden(t *testing.T) {
	stop := func(t *testing.T, db *corrosion.Client) {
		t.Helper()
		if err := corrosion.UpdateVMStateStrict(context.Background(), db, "vm1", "stopped", "operator-stop"); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("before the define", func(t *testing.T) {
		db, fake, r, _ := supersededFixture(t, "starting")
		r.diskStat = func(p string) (os.FileInfo, error) { stop(t, db); return os.Stat(p) }
		fresh, _ := corrosion.GetVM(context.Background(), db, "vm1")
		r.startPendingVM(context.Background(), *fresh)
		if startedOrDefined(fake, "vm1") {
			t.Fatal("a start stopped before its define defined or started the VM")
		}
	})
	t.Run("before the boot", func(t *testing.T) {
		db, fake, r, _ := supersededFixture(t, "starting")
		r.startDomainHook = func(context.Context) { stop(t, db) }
		fresh, _ := corrosion.GetVM(context.Background(), db, "vm1")
		r.startPendingVM(context.Background(), *fresh)
		for _, e := range fake.EventLog() {
			if e.Domain == "vm1" && e.Op == "start" {
				t.Fatal("a start stopped before its boot started the VM")
			}
		}
		if fake.DomainExists("vm1") {
			t.Fatal("the definition this start made was left behind")
		}
		if vm, _ := corrosion.GetVM(context.Background(), db, "vm1"); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
			t.Fatalf("row %q/%q, want the stop kept", vm.State, vm.StateDetail)
		}
	})
}
