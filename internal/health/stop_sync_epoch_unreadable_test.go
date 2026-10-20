package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// With owner-epoch enforcement on, an out-of-band stop sync whose epoch read
// fails is not published this pass: the plain statement would carry no epoch,
// and peers apply it unfenced. The next pass reads the row again.
//
// The read is made to fail and the write not: a column only the read selects
// is hidden at the replica-freshness check, the last call before the read.
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
	hidden := false
	r.SetReplicaFreshness(func() (bool, string) {
		if !hidden {
			hidden = true
			if err := db.Execute(ctx, `ALTER TABLE vms RENAME COLUMN stack_name TO stack_name_hidden`); err != nil {
				t.Errorf("hide stack_name: %v", err)
			}
		}
		return true, ""
	})
	r.ReconcileOnce(ctx)
	if !hidden {
		t.Fatal("the stop sync never reached its replica-freshness check; the scenario did not run")
	}
	rows, err := db.Query(ctx, `SELECT state FROM vms WHERE name = 'vm1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read vm1's state: %v (%d rows)", err, len(rows))
	}
	if st := rows[0].String("state"); st != "running" {
		t.Fatalf("vm1 = %s after a stop sync whose owner epoch could not be read; want it left running for the next pass", st)
	}

	// With the epoch readable, the same pass records the stop, fenced by it.
	db2, r2 := stopSyncFixture(t)
	r2.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
	r2.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, db2, "vm1"); vm == nil || vm.State == "running" {
		t.Fatalf("vm1 after a readable stop sync = %+v; want it recorded stopped", vm)
	}
}
