package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// With owner-epoch enforcement on, an out-of-band stop sync whose epoch read
// fails is not published this pass: the plain statement would carry no epoch,
// and peers apply it unfenced. The next pass reads the row again.
//
// Mutation: the read error taken as "no epoch" (the plain write) — vm1 is
// recorded stopped, red.
func TestStopSync_EpochUnreadableWithEnforcementSkipsThePass(t *testing.T) {
	db, r := stopSyncFixture(t)
	ctx := context.Background()
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	read := false
	orig := stopSyncEpochRead
	stopSyncEpochRead = func(context.Context, *corrosion.Client, string) (*corrosion.VMRecord, error) {
		read = true
		return nil, errors.New("database is locked")
	}
	t.Cleanup(func() { stopSyncEpochRead = orig })
	r.ReconcileOnce(ctx)
	stopSyncEpochRead = orig
	if !read {
		t.Fatal("the stop sync never read the owner epoch; the scenario did not run")
	}
	vm, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "running" {
		t.Fatalf("vm1 = %s after a stop sync whose owner epoch could not be read; want it left running for the next pass", vm.State)
	}

	// With the epoch readable, the same pass records the stop, fenced by it.
	db2, r2 := stopSyncFixture(t)
	r2.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	r2.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, db2, "vm1"); vm == nil || vm.State == "running" {
		t.Fatalf("vm1 after a readable stop sync = %+v; want it recorded stopped", vm)
	}
}
